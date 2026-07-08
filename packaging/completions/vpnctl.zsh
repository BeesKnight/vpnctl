#compdef vpnctl
# zsh completion for vpnctl — installed as $fpath/_vpnctl (the filename,
# not this source name, is what zsh's autoload mechanism requires).

_vpnctl() {
    local -a commands
    commands=(
        'list:list all profiles'
        'ls:list all profiles'
        'use:activate a profile'
        'down:deactivate the active profile'
        'status:show active profile / kill-switch state'
        'test:test external connectivity through the active profile'
        'run:run a command through the active profile'
        'import:import profiles from a subscription link or file'
        'export:print a profile'"'"'s underlying config file'
        'insecure:toggle TLS certificate verification for a profile'
        'ps:list processes launched through the active profile'
        'kill:kill a process launched through the active profile'
        'doctor:check system dependencies and configuration'
        'bench:activate each profile in turn and rank by latency'
        'logs:show the active engine'"'"'s recent log output'
        'help:show usage'
    )

    if (( CURRENT == 2 )); then
        _describe 'command' commands
        return
    fi

    case "${words[2]}" in
        use|export)
            local -a profiles
            profiles=(${(f)"$(vpnctl __complete_profiles 2>/dev/null)"})
            _describe 'profile' profiles
            ;;
        insecure)
            if (( CURRENT == 3 )); then
                local -a profiles
                profiles=(${(f)"$(vpnctl __complete_profiles 2>/dev/null)"})
                _describe 'profile' profiles
            elif (( CURRENT == 4 )); then
                _values 'insecure options' 'off'
            fi
            ;;
        run)
            _values 'run options' '--tui' '--gui' '--'
            ;;
        import)
            _values 'import options' '--sub' '--wg'
            ;;
        logs)
            _values 'logs options' '-f' '--follow'
            ;;
        doctor)
            _values 'doctor options' '--fix'
            ;;
        export)
            _values 'export options' '--out'
            ;;
    esac
}

_vpnctl "$@"
