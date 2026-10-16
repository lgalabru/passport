use clap::Args;

#[derive(Args, Debug)]
pub struct CompletionsCommand {
    /// Shell to generate completions for
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

impl CompletionsCommand {
    pub fn execute(&self, cmd: &mut clap::Command) {
        clap_complete::generate(self.shell, cmd, "passport", &mut std::io::stdout());
    }
}
