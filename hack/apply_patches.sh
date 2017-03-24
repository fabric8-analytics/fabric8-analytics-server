#!/usr/bin/bash -e

HERE=$(dirname $0)

patches_dir="${HERE}/patches"

# list of all patches in directory
patches=$(ls $patches_dir/*.patch 2>/dev/null)

# not patches -> exit
[[ -z "${patches}" ]] && exit 0

for i in ${patches}
do
  # apply patch
  patch -p1 --directory /usr/lib/python3.4/site-packages/ < "${i}"
done

exit 0
