# bash completion for vpnctl
#
# Dynamic profile names come from `vpnctl __complete_profiles`, a hidden
# subcommand (not in `vpnctl help`) that just prints one profile name per
# line — the daemon isn't involved, this reads the same
# ~/.config/vpnctl/profiles/ directory `vpnctl use` resolves against.
_vpnctl_complete() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD - 1]}"

    local commands="list ls use down status test run import export insecure ps kill doctor bench logs help"

    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=($(compgen -W "$commands" -- "$cur"))
        return 0
    fi

    case "${COMP_WORDS[1]}" in
        use|export)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=($(compgen -W "$(vpnctl __complete_profiles 2>/dev/null)" -- "$cur"))
            fi
            ;;
        insecure)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=($(compgen -W "$(vpnctl __complete_profiles 2>/dev/null)" -- "$cur"))
            elif [ "$COMP_CWORD" -eq 3 ]; then
                COMPREPLY=($(compgen -W "off" -- "$cur"))
            fi
            ;;
        run)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=($(compgen -W "--tui --gui --" -- "$cur"))
            fi
            ;;
        import)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=($(compgen -W "--sub --wg" -- "$cur"))
            fi
            ;;
        logs)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=($(compgen -W "-f --follow" -- "$cur"))
            fi
            ;;
        doctor)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=($(compgen -W "--fix" -- "$cur"))
            fi
            ;;
        export)
            if [ "$COMP_CWORD" -eq 3 ]; then
                COMPREPLY=($(compgen -W "--out" -- "$cur"))
            fi
            ;;
        kill)
            # PIDs/process names require a running daemon and an active
            # profile to enumerate (`vpnctl ps`) — left uncompleted rather
            # than shelling out mid-keystroke to a socket that may not
            # exist.
            ;;
    esac
    return 0
}
complete -F _vpnctl_complete vpnctl
