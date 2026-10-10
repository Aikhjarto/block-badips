# bash completion for block-badips.sh                        -*- shell-script -*-

# block-badips.sh takes no arguments, so complete nothing instead of file names
_block_badips()
{
    COMPREPLY=()
}
complete -F _block_badips block-badips.sh
