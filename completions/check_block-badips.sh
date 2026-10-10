# bash completion for check_block-badips.sh                  -*- shell-script -*-

_check_block_badips()
{
    local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
    COMPREPLY=()

    case $prev in
        -w | -c | -W | -C | -f)
            return
            ;;
    esac

    # no positional arguments: offer the options
    mapfile -t COMPREPLY < <(compgen -W '-h -w -c -W -C -f' -- "$cur")
}
complete -F _check_block_badips check_block-badips.sh
