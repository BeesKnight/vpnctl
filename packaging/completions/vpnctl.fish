# fish completion for vpnctl
set -l __vpnctl_commands list ls use down status test run import export insecure ps kill doctor bench logs help

complete -c vpnctl -f

complete -c vpnctl -n "not __fish_seen_subcommand_from $__vpnctl_commands" -a list -d "list all profiles"
complete -c vpnctl -n "not __fish_seen_subcommand_from $__vpnctl_commands" -a ls -d "list all profiles"
complete -c vpnctl -n "not __fish_seen_subcommand_from $__vpnctl_commands" -a use -d "activate a profile"
complete -c vpnctl -n "not __fish_seen_subcommand_from $__vpnctl_commands" -a down -d "deactivate the active profile"
complete -c vpnctl -n "not __fish_seen_subcommand_from $__vpnctl_commands" -a status -d "show active profile state"
complete -c vpnctl -n "not __fish_seen_subcommand_from $__vpnctl_commands" -a test -d "test connectivity through the active profile"
complete -c vpnctl -n "not __fish_seen_subcommand_from $__vpnctl_commands" -a run -d "run a command through the active profile"
complete -c vpnctl -n "not __fish_seen_subcommand_from $__vpnctl_commands" -a import -d "import profiles from a subscription or file"
complete -c vpnctl -n "not __fish_seen_subcommand_from $__vpnctl_commands" -a export -d "print a profile's underlying config file"
complete -c vpnctl -n "not __fish_seen_subcommand_from $__vpnctl_commands" -a insecure -d "toggle TLS certificate verification"
complete -c vpnctl -n "not __fish_seen_subcommand_from $__vpnctl_commands" -a ps -d "list running processes"
complete -c vpnctl -n "not __fish_seen_subcommand_from $__vpnctl_commands" -a kill -d "kill a process"
complete -c vpnctl -n "not __fish_seen_subcommand_from $__vpnctl_commands" -a doctor -d "check system dependencies"
complete -c vpnctl -n "not __fish_seen_subcommand_from $__vpnctl_commands" -a bench -d "activate each profile in turn and rank by latency"
complete -c vpnctl -n "not __fish_seen_subcommand_from $__vpnctl_commands" -a logs -d "show the active engine's recent log output"
complete -c vpnctl -n "not __fish_seen_subcommand_from $__vpnctl_commands" -a help -d "show usage"

complete -c vpnctl -n "__fish_seen_subcommand_from use" -a "(vpnctl __complete_profiles 2>/dev/null)"
complete -c vpnctl -n "__fish_seen_subcommand_from export" -a "(vpnctl __complete_profiles 2>/dev/null)"
complete -c vpnctl -n "__fish_seen_subcommand_from insecure" -a "(vpnctl __complete_profiles 2>/dev/null)"
complete -c vpnctl -n "__fish_seen_subcommand_from run" -a "--tui --gui --"
complete -c vpnctl -n "__fish_seen_subcommand_from import" -a "--sub --wg"
complete -c vpnctl -n "__fish_seen_subcommand_from export" -a "--out"
complete -c vpnctl -n "__fish_seen_subcommand_from logs" -a "-f --follow"
