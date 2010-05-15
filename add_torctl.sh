#!/bin/sh
#
# Run this to grab the TorCtl source and set up a
# git hook to fetch TorCtl after every merge.
#

if [ ! -f .gitmodules ]
then
    exit 1
fi

# Get TorCtl (assumes .gitmodules exists)
git submodule init
git submodule update

# Create the hook
cat <<EOF >.git/hooks/post-merge
#!/bin/sh

if [ "x\$(git config core.bare)" = "xfalse" ]
then
    grep submodule .git/config >/dev/null
    if [ \$? -ne 0 ]
    then
        git submodule init
    fi
    git submodule update
fi
EOF

# Make it executable
chmod +x .git/hooks/post-merge

