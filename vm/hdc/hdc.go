// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package hdc implements a syzkaller VM backend that drives a physical or
// emulated OpenHarmony / HarmonyOS device over the `hdc` (OpenHarmony Device
// Connector) bridge, the OpenHarmony counterpart of Android's `adb`.
//
// It targets the OpenHarmony "standard system" kernel, which is a Linux kernel
// (5.10 LTS at the time of writing) carrying the OpenHarmony patch set (HDF
// drivers, ashmem, dma-buf heaps, the code_sign/xpm/dec security modules, ...).
// On such a target syzkaller works exactly like on any other arm64/amd64 Linux
// box: coverage is collected via KCOV and crashes via the kernel log.
//
// NOTE: the flagship "HarmonyOS NEXT" microkernel (HongMeng) is NOT a Linux
// kernel and is out of reach of this backend (no KCOV, closed syscall ABI).
// See docs/harmonyos/setup_harmonyos_hdc.md for the full scope discussion.
//
// This file is a close adaptation of vm/adb/adb.go; the Android-specific bits
// (A/B slot bookkeeping, `dumpsys battery`, Android properties) are dropped and
// every bridge invocation is translated to its hdc equivalent:
//
//	adb -s DEV shell CMD      ->  hdc -t DEV shell CMD
//	adb -s DEV push  SRC DST  ->  hdc -t DEV file send SRC DST
//	adb -s DEV reverse R L    ->  hdc -t DEV rport R L
//	adb -s DEV wait-for-device->  hdc -t DEV wait
//	adb root                  ->  hdc -t DEV smode
//	adb reboot                ->  hdc -t DEV target boot
package hdc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
)

func init() {
	vmimpl.Register("hdc", vmimpl.Type{
		Ctor: ctor,
	})
}

// deviceTmpDir is the hdc-writable, exec-capable scratch directory on the
// device where syz-executor and related binaries are pushed and run from.
const deviceTmpDir = "/data/local/tmp"

type Device struct {
	Serial     string   `json:"serial"`      // device connect key (USB serial or ip:port)
	Console    string   `json:"console"`     // serial console device name (e.g. "/dev/ttyUSB0")
	ConsoleCmd []string `json:"console_cmd"` // command to obtain device console log
}

type Config struct {
	Hdc     string            `json:"hdc"`     // hdc binary name/path ("hdc" by default)
	Devices []json.RawMessage `json:"devices"` // list of hdc devices to use

	// If this option is set (default), the device is rebooted after each crash.
	// Set it to false to disable reboots.
	TargetReboot  bool   `json:"target_reboot"`
	RepairScript  string `json:"repair_script"`  // script to execute before each startup
	StartupScript string `json:"startup_script"` // script to execute after each startup
	// BootService specifies the process name to wait for during boot completion.
	// The default value is "foundation", the OpenHarmony process that hosts the
	// core system-ability services and comes up late in boot.
	BootService string `json:"boot_service"`
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
}

type instance struct {
	cfg        *Config
	hdcBin     string
	device     string
	console    string
	consoleCmd []string
	closed     chan bool
	debug      bool
	timeouts   targets.Timeouts
}

var (
	// USB connect keys are alphanumeric; TCP connect keys are ip:port
	// (e.g. the local emulator on 127.0.0.1:5555).
	deviceSerial = "^[0-9A-Za-z]+$"
	ipAddress    = `^(?:localhost|(?:[0-9]{1,3}\.){3}[0-9]{1,3})\:(?:[0-9]{1,5})$`
)

func loadDevice(data []byte) (*Device, error) {
	devObj := &Device{}
	var devStr string
	err1 := config.LoadData(data, devObj)
	err2 := config.LoadData(data, &devStr)
	if err1 != nil && err2 != nil {
		return nil, fmt.Errorf("failed to parse hdc vm config: %w %w", err1, err2)
	}
	if err2 == nil {
		devObj.Serial = devStr
	}
	return devObj, nil
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{
		Hdc:          "hdc",
		TargetReboot: true,
		BootService:  "foundation",
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse hdc vm config: %w", err)
	}
	if _, err := exec.LookPath(cfg.Hdc); err != nil {
		return nil, err
	}
	if len(cfg.Devices) == 0 {
		return nil, fmt.Errorf("no hdc devices specified")
	}
	devRe := regexp.MustCompile(fmt.Sprintf("%s|%s", deviceSerial, ipAddress))
	for _, dev := range cfg.Devices {
		device, err := loadDevice(dev)
		if err != nil {
			return nil, err
		}
		if !devRe.MatchString(device.Serial) {
			return nil, fmt.Errorf("invalid hdc device id '%v'", device.Serial)
		}
	}
	pool := &Pool{
		cfg: cfg,
		env: env,
	}
	return pool, nil
}

func (pool *Pool) Count() int {
	return len(pool.cfg.Devices)
}

func (pool *Pool) Create(_ context.Context, workdir string, index int) (vmimpl.Instance, error) {
	device, err := loadDevice(pool.cfg.Devices[index])
	if err != nil {
		return nil, err
	}
	inst := &instance{
		cfg:        pool.cfg,
		hdcBin:     pool.cfg.Hdc,
		device:     device.Serial,
		console:    device.Console,
		consoleCmd: device.ConsoleCmd,
		closed:     make(chan bool),
		debug:      pool.env.Debug,
		timeouts:   pool.env.Timeouts,
	}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()
	if err := inst.repair(); err != nil {
		return nil, err
	}
	if len(inst.consoleCmd) > 0 {
		log.Logf(0, "associating hdc device %v with console cmd `%v`", inst.device, inst.consoleCmd)
	} else {
		if inst.console == "" {
			// More verbose log level is required, otherwise echo to /dev/kmsg won't show.
			level, err := inst.hdc("shell", "cat /proc/sys/kernel/printk")
			if err != nil {
				return nil, fmt.Errorf("failed to read /proc/sys/kernel/printk: %w", err)
			}
			inst.hdc("shell", "echo 8 > /proc/sys/kernel/printk")
			inst.console = findConsole(inst.hdcBin, inst.device)
			// Verbose kmsg slows down system, so disable it after findConsole.
			inst.hdc("shell", fmt.Sprintf("echo %v > /proc/sys/kernel/printk", string(level)))
		}
		log.Logf(0, "associating hdc device %v with console %v", inst.device, inst.console)
	}
	// Remove temp files from previous runs.
	// rm chokes on bad symlinks so we must remove them first.
	if _, err := inst.hdc("shell", "ls "+deviceTmpDir+"/syzkaller*"); err == nil {
		if _, err := inst.hdc("shell", "find "+deviceTmpDir+"/syzkaller* -type l -exec unlink {} \\;"+
			" && rm -Rf "+deviceTmpDir+"/syzkaller*"); err != nil {
			return nil, err
		}
	}
	inst.hdc("shell", "echo 0 > /proc/sys/kernel/kptr_restrict")
	closeInst = nil
	return inst, nil
}

var (
	consoleCacheMu sync.Mutex
	consoleToDev   = make(map[string]string)
	devToConsole   = make(map[string]string)
)

func parseHdcOutToInt(out []byte) int {
	val := 0
	for _, c := range out {
		if c >= '0' && c <= '9' {
			val = val*10 + int(c) - '0'
			continue
		}
		if val != 0 {
			break
		}
	}
	return val
}

// findConsole returns the serial console file associated with the dev device
// (e.g. /dev/ttyUSB0). We write a unique marker to the device's /dev/kmsg via
// `hdc shell` and observe on which host serial device the marker appears.
func findConsole(hdc, dev string) string {
	consoleCacheMu.Lock()
	defer consoleCacheMu.Unlock()
	if con := devToConsole[dev]; con != "" {
		return con
	}
	con, err := findConsoleImpl(hdc, dev)
	if err != nil {
		log.Logf(0, "failed to associate hdc device %v with console: %v", dev, err)
		log.Logf(0, "falling back to 'hdc shell dmesg -w'")
		log.Logf(0, "note: some bugs may be detected as 'lost connection to test machine' with no kernel output")
		con = "hdc"
		devToConsole[dev] = con
		return con
	}
	devToConsole[dev] = con
	consoleToDev[con] = dev
	return con
}

func findConsoleImpl(hdc, dev string) (string, error) {
	// Attempt to find an exact match, at /dev/ttyUSB.{SERIAL}
	// This is something that can be set up on Linux via 'udev' rules.
	exactCon := "/dev/ttyUSB." + dev
	if osutil.IsExist(exactCon) {
		return exactCon, nil
	}

	// Search all consoles.
	consoles, err := filepath.Glob("/dev/ttyUSB*")
	if err != nil {
		return "", fmt.Errorf("failed to list /dev/ttyUSB devices: %w", err)
	}
	output := make(map[string]*[]byte)
	errorsCh := make(chan error, len(consoles))
	done := make(chan bool)
	for _, con := range consoles {
		if consoleToDev[con] != "" {
			continue
		}
		out := new([]byte)
		output[con] = out
		go func(con string) {
			tty, err := vmimpl.OpenConsole(con)
			if err != nil {
				errorsCh <- err
				return
			}
			defer tty.Close()
			go func() {
				<-done
				tty.Close()
			}()
			*out, _ = io.ReadAll(tty)
			errorsCh <- nil
		}(con)
	}
	if len(output) == 0 {
		return "", fmt.Errorf("no unassociated console devices left")
	}
	time.Sleep(500 * time.Millisecond)
	unique := fmt.Sprintf(">>>%v<<<", dev)
	cmd := osutil.Command(hdc, "-t", dev, "shell", "echo", "\"<1>", unique, "\"", ">", "/dev/kmsg")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("failed to run hdc shell: %w\n%s", err, out)
	}
	time.Sleep(500 * time.Millisecond)
	close(done)

	var anyErr error
	for range output {
		err := <-errorsCh
		if anyErr == nil && err != nil {
			anyErr = err
		}
	}

	con := ""
	for con1, out := range output {
		if bytes.Contains(*out, []byte(unique)) {
			if con == "" {
				con = con1
			} else {
				anyErr = fmt.Errorf("device is associated with several consoles: %v and %v", con, con1)
			}
		}
	}

	if con == "" {
		if anyErr != nil {
			return "", anyErr
		}
		return "", fmt.Errorf("no console is associated with this device")
	}
	return con, nil
}

func (inst *instance) Forward(port int) (string, error) {
	var err error
	for range 1000 {
		devicePort := vmimpl.RandomPort()
		// `hdc rport REMOTE LOCAL` reserves device-side REMOTE traffic to the
		// host-side LOCAL address (the reverse tunnel syzkaller needs so the
		// on-device executor can reach syz-manager's RPC port on the host).
		_, err = inst.hdc("rport", fmt.Sprintf("tcp:%v", devicePort), fmt.Sprintf("tcp:%v", port))
		if err == nil {
			return fmt.Sprintf("127.0.0.1:%v", devicePort), nil
		}
	}
	return "", err
}

func (inst *instance) hdc(args ...string) ([]byte, error) {
	return inst.hdcWithTimeout(time.Minute, args...)
}

func (inst *instance) hdcWithTimeout(timeout time.Duration, args ...string) ([]byte, error) {
	if inst.debug {
		log.Logf(0, "executing hdc %+v", args)
	}
	args = append([]string{"-t", inst.device}, args...)
	out, err := osutil.RunCmd(timeout, "", inst.hdcBin, args...)
	if inst.debug {
		log.Logf(0, "hdc returned")
	}
	return out, err
}

func (inst *instance) waitForBootCompletion() {
	// hdc connects to a device and starts syz-executor while the device may
	// still be booting, which can race system initialization. To determine
	// whether the system has come up we wait for the process named by
	// BootService (default 'foundation') to appear.
	log.Logf(2, "waiting for boot completion")
	bootService := inst.cfg.BootService
	if bootService == "" {
		return
	}
	sleepTime := 5
	sleepDuration := time.Duration(sleepTime) * time.Second
	maxWaitTime := 60 * 3 // 3 minutes to wait until boot completion
	maxRetries := maxWaitTime / sleepTime
	i := 0
	for ; i < maxRetries; i++ {
		time.Sleep(sleepDuration)

		if out, err := inst.hdc("shell", fmt.Sprintf("pgrep %s | wc -l", bootService)); err == nil {
			count := parseHdcOutToInt(out)
			if count != 0 {
				log.Logf(0, "boot completed")
				break
			}
		} else {
			log.Logf(0, "failed to execute command 'pgrep %s | wc -l', %v", bootService, err)
			break
		}
	}
	if i == maxRetries {
		log.Logf(0, "failed to determine boot completion, can't find '%s' process", bootService)
	}
}

func (inst *instance) repair() error {
	// Assume that the device is in a bad state initially and reboot it.
	// Ignore errors, maybe we will manage to reboot it anyway.
	if inst.cfg.RepairScript != "" {
		if err := inst.runScript(inst.cfg.RepairScript); err != nil {
			return err
		}
	}
	inst.waitForDevice()
	if inst.cfg.TargetReboot {
		if _, err := inst.hdc("target", "boot"); err != nil {
			var verboseErr *osutil.VerboseError
			if !errors.As(err, &verboseErr) {
				return err
			}
			if verboseErr.ExitCode != 0 && verboseErr.ExitCode != 255 {
				return err
			}
		}
		// Now give it time to boot.
		if !vmimpl.SleepInterruptible(10 * time.Second) {
			return fmt.Errorf("shutdown in progress")
		}
		if err := inst.waitForDevice(); err != nil {
			return err
		}
	}
	// Restart the hdc daemon with root permissions (no-op if already root,
	// e.g. on the emulator). Best-effort: userdebug/eng images only.
	inst.hdc("smode")
	inst.waitForDevice()
	inst.waitForBootCompletion()

	// Mount debugfs so the executor can reach /sys/kernel/debug/kcov.
	if _, err := inst.hdc("shell", "ls /sys/kernel/debug"); err != nil {
		log.Logf(2, "debugfs was unmounted, mounting")
		if _, err := inst.hdc("shell", "mount -t debugfs debugfs /sys/kernel/debug "+
			"&& chmod 0755 /sys/kernel/debug"); err != nil {
			return err
		}
	}
	if inst.cfg.StartupScript != "" {
		if err := inst.runScript(inst.cfg.StartupScript); err != nil {
			return err
		}
	}
	return nil
}

func (inst *instance) runScript(script string) error {
	log.Logf(2, "hdc: executing %s", script)
	output, err := osutil.RunCmd(5*time.Minute, "", "sh", script, inst.device, inst.console)
	if err != nil {
		return fmt.Errorf("failed to execute %s: %w", script, err)
	}
	log.Logf(2, "hdc: execute %s output\n%s", script, output)
	log.Logf(2, "hdc: done executing %s", script)
	return nil
}

func (inst *instance) waitForDevice() error {
	if !vmimpl.SleepInterruptible(time.Second) {
		return fmt.Errorf("shutdown in progress")
	}
	if _, err := inst.hdcWithTimeout(10*time.Minute, "wait"); err != nil {
		return fmt.Errorf("instance is dead and unrepairable: %w", err)
	}
	return nil
}

func (inst *instance) Close() error {
	close(inst.closed)
	return nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := filepath.Join(deviceTmpDir, filepath.Base(hostSrc))
	if _, err := inst.hdc("file", "send", hostSrc, vmDst); err != nil {
		return "", err
	}
	inst.hdc("shell", "chmod", "+x", vmDst)
	return vmDst, nil
}

func (inst *instance) Run(ctx context.Context, command string) (
	<-chan vmimpl.Chunk, <-chan error, error) {
	var tty io.ReadCloser
	var err error

	if len(inst.consoleCmd) > 0 {
		tty, err = vmimpl.OpenConsoleByCmd(inst.consoleCmd[0], inst.consoleCmd[1:])
	} else if inst.console == "hdc" {
		// Fallback console: stream the kernel ring buffer over `hdc shell dmesg -w`.
		tty, err = vmimpl.OpenConsoleByCmd(inst.hdcBin, []string{"-t", inst.device, "shell", "dmesg -w"})
	} else {
		tty, err = vmimpl.OpenConsole(inst.console)
	}
	if err != nil {
		return nil, nil, err
	}

	hdcRpipe, hdcWpipe, err := osutil.LongPipe()
	if err != nil {
		tty.Close()
		return nil, nil, err
	}
	hdcRpipeErr, hdcWpipeErr, err := osutil.LongPipe()
	if err != nil {
		tty.Close()
		hdcRpipe.Close()
		hdcWpipe.Close()
		return nil, nil, err
	}
	if inst.debug {
		log.Logf(0, "starting: hdc shell %v", command)
	}
	hdc := osutil.Command(inst.hdcBin, "-t", inst.device, "shell", "cd "+deviceTmpDir+"; "+command)
	hdc.Stdout = hdcWpipe
	hdc.Stderr = hdcWpipeErr
	if err := hdc.Start(); err != nil {
		tty.Close()
		hdcRpipe.Close()
		hdcWpipe.Close()
		hdcRpipeErr.Close()
		hdcWpipeErr.Close()
		return nil, nil, fmt.Errorf("failed to start hdc: %w", err)
	}
	hdcWpipe.Close()
	hdcWpipeErr.Close()

	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	merger := vmimpl.NewOutputMerger(tee)
	merger.Add("console", vmimpl.OutputConsole, tty)
	merger.Add("hdc", vmimpl.OutputStdout, hdcRpipe)
	merger.Add("hdc-err", vmimpl.OutputStderr, hdcRpipeErr)

	return vmimpl.Multiplex(ctx, hdc, merger, vmimpl.MultiplexConfig{
		Console: tty,
		Close:   inst.closed,
		Debug:   inst.debug,
		Scale:   inst.timeouts.Scale,
	})
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	return nil, false
}
