use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

use clap::Parser;
use cursive::{
    event::Event,
    theme::PaletteStyle,
    view::Nameable,
    views::{Dialog, EditView, LinearLayout, ListView, Panel, ScreensView, TextView},
    Cursive, CursiveExt,
};
use soil_vm::{syscalls::SyscallHandler, Vm};

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the binary to be run
    path: PathBuf,
    /// Prints register states after each instruction
    #[arg(short = 'v')]
    dbg_instrs: bool,
}

enum VmState {
    Initialized,
    Running,
    Panicked,
    Exited,
}

#[derive(Default)]
struct DebuggerData {
    running: bool,
    previous: usize,
    breakpoints: Vec<usize>,
}

pub struct DebugSyscallHandler {}

impl SyscallHandler for DebugSyscallHandler {
    fn handle_syscall(
        &self,
        number: u8,
        registers: &mut [soil_vm::Register; 8],
        memory: &mut [u8],
        ip: &mut usize,
    ) -> Result<(), soil_vm::Trap> {
        match number {
            0 => return Err(soil_vm::Trap::Exited),
            _ => return Err(soil_vm::Trap::UnknownSyscall(number)),
        }
        Ok(())
    }
}

fn main() {
    let args = Args::parse();
    let binary = std::fs::read(args.path).unwrap();
    let bytecode = soil::parse::parse(binary).unwrap();
    let syscalls = DebugSyscallHandler {};
    let vm = Arc::new(RwLock::new(Vm::with_syscalls(
        bytecode.clone(),
        syscalls,
        args.dbg_instrs,
    )));

    let mut siv = Cursive::new();
    siv.set_user_data(DebuggerData::default());
    siv.set_autorefresh(true);

    let mut bytecode_view = ListView::new();
    for (idx, instr) in bytecode.bytecode().unwrap().iter().enumerate() {
        bytecode_view.add_child(
            format!("(0x{:02x})", instr.location),
            TextView::new(format!("{:?}", instr.kind)).with_name(format!("instr_{idx}")),
        )
    }

    let mut internals_view = LinearLayout::vertical()
        .child(
            Panel::new(TextView::new(vm.read().unwrap().format_status()).with_name("regs"))
                .title("Registers"),
        )
        .child(Panel::new(TextView::new("Running").with_name("vm_state")));
    if let Some(labels) = bytecode.labels() {
        let mut list = ListView::new();
        for l in labels {
            list.add_child(
                format!("(0x{:02x})", l.position),
                TextView::new(format!("{}", l.name)),
            );
        }
        internals_view.add_child(Panel::new(list).title("Labels"));
    }

    let mut screens = ScreensView::single_screen(
        Panel::new(
            LinearLayout::horizontal()
                .child(Panel::new(bytecode_view).title("Bytecode"))
                .child(internals_view),
        )
        .title("Main View"),
    );

    screens.add_screen(
        Panel::new(LinearLayout::vertical().child(TextView::new("Breakpoints")))
            .title("Breakpoints"),
    );

    siv.add_layer(
        LinearLayout::vertical()
            .child(screens.with_name("screens"))
            .child(TextView::new("[q]uit [s]tep [r]un")),
    );

    let vmc = Arc::clone(&vm);
    siv.add_global_callback('q', |s| s.quit());
    siv.add_global_callback('s', move |s| {
        let data = s.user_data::<DebuggerData>().unwrap();
        let previous = data.previous;
        if let Err(e) = vmc.write().unwrap().step() {
            s.call_on_name("vm_state", |v: &mut TextView| {
                v.set_content(format!("Exited: {e:?}"))
            });
        }
        s.call_on_name("regs", |v: &mut TextView| {
            v.set_content(vmc.read().unwrap().format_status())
        });
        let ip = vmc.read().unwrap().ip();
        s.call_on_name(&format!("instr_{ip}"), |v: &mut TextView| {
            v.set_style(PaletteStyle::Highlight);
        });
        s.call_on_name(&format!("instr_{}", previous), |v: &mut TextView| {
            v.set_style(PaletteStyle::Primary);
        });
        let data = s.user_data::<DebuggerData>().unwrap();
        data.previous = ip;
    });
    let vmc = Arc::clone(&vm);
    siv.add_global_callback(Event::Refresh, move |s| {
        let data = s.user_data::<DebuggerData>().unwrap();
        let previous = data.previous;
        if !data.running {
            return;
        }
        if let Err(e) = vmc.write().unwrap().step() {
            match e {
                soil_vm::Trap::Breakpoint => {
                    data.running = false;
                }
                t => {
                    s.call_on_name("vm_state", |v: &mut TextView| {
                        v.set_content(format!("Exited: {t:?}"))
                    });
                }
            }
        }
        s.call_on_name("regs", |v: &mut TextView| {
            v.set_content(vmc.read().unwrap().format_status())
        });
        let ip = vmc.read().unwrap().ip();
        s.call_on_name(&format!("instr_{ip}"), |v: &mut TextView| {
            v.set_style(PaletteStyle::Highlight);
        });
        s.call_on_name(&format!("instr_{}", previous), |v: &mut TextView| {
            v.set_style(PaletteStyle::Primary);
        });
        let data = s.user_data::<DebuggerData>().unwrap();
        data.previous = ip;
    });
    siv.add_global_callback('r', move |s| {
        if let Some(data) = s.user_data::<DebuggerData>() {
            data.running = !data.running;
        }
    });
    let vmc = Arc::clone(&vm);
    siv.add_global_callback('b', move |s| {
        let vm = Arc::clone(&vmc);
        let vm2 = Arc::clone(&vmc);
        s.add_layer(
            Dialog::new()
                .content(
                    LinearLayout::vertical()
                        .child(TextView::new("Create breakpoint"))
                        .child(
                            EditView::new()
                                .on_submit(move |s, text| {
                                    let data = s.user_data::<DebuggerData>().unwrap();
                                    let target = usize::from_str_radix(text, 16).unwrap();
                                    data.breakpoints.push(target);
                                    vm2.write().unwrap().set_breakpoint(target);
                                    s.pop_layer();
                                })
                                .with_name("breakpoint_location"),
                        ),
                )
                .button("Confirm", move |s| {
                    let text = s
                        .call_on_name("breakpoint_location", |v: &mut EditView| v.get_content())
                        .unwrap();
                    let data = s.user_data::<DebuggerData>().unwrap();
                    let target = usize::from_str_radix(text.as_str(), 16).unwrap();
                    data.breakpoints.push(target);
                    vm.write().unwrap().set_breakpoint(target);
                    s.pop_layer();
                })
                .dismiss_button("Cancel"),
        );
        let data = s.user_data::<DebuggerData>().unwrap();
    });
    siv.add_global_callback(Event::Key(cursive::event::Key::F1), |s| {
        s.call_on_name("screens", |v: &mut ScreensView<Panel<LinearLayout>>| {
            v.set_active_screen(0)
        });
    });
    siv.add_global_callback(Event::Key(cursive::event::Key::F2), |s| {
        s.call_on_name("screens", |v: &mut ScreensView<Panel<LinearLayout>>| {
            v.set_active_screen(1)
        });
    });
    siv.run();
}
