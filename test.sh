#!/bin/bash

BINARY="./assa"
TEST_PATH="tc"

user_input ()
{
	args="${@:2}"
	while [ true ]; do
		answer=""
		printf "~> "

		if [ "$1" ]; then
			args="${@:1}"
			read answer
			if [ "$answer" == "" ]; then
				answer=$1
				echo -en "\033[1A\033[2K"
				echo "~> $1"
				break
			fi
		else
			while [ true ]; do
				read answer
				if [ "$answer" == "" ]; then
					echo "${bold}Invalid input!${normal}"
					printf "~> "
				else
					break
				fi
			done
		fi

		if [ "$2" ]; then
			for arg in $args; do
				if [ "$arg" == "_NUM" ] && [ "${answer##*[!0-9]*}" ]; then
					break 2
				elif [ "${arg,,}" == "${answer,,}" ]; then
					break 2
				fi
			done
			echo "${bold}Invalid input!${normal}"
		else
			break
		fi
	done
}

normal=$(tput sgr0)
bold=$(tput bold)

mkdir -p "$TEST_PATH/user"
for f in $TEST_PATH/in/*.txt; do
	if [[ "$(basename "$f")" =~ in(.*)\.txt ]]; then
		case=${BASH_REMATCH[1]}
	fi

	ref="$TEST_PATH/ref/out${case}.txt"
	user="$TEST_PATH/user/out${case}.txt"

	$BINARY < "$f" > "$user"
	assa_ret=$?

	if cmp -s "$ref" "$user"; then
		echo "Test Case '${case}' completed successfully with return code ${assa_ret}"
	else
		echo "Test Case '${case}' failed with return code ${assa_ret}"
		echo "Examine diff? [${bold}vimdiff${normal}/diff/no]"
		user_input "vimdiff" "diff" "no" "n" "yes" "y"
		if [ "${answer,,}" == "vimdiff" ] || [ "${answer,,}" == "yes" ] || [ "${answer,,}" == "y" ]; then
			vimdiff "$ref" "$user"
		elif [ "${answer,,}" == "diff" ]; then
			diff "$ref" "$user"
			read
		fi
	fi
done
rm -r "$TEST_PATH/user"
