#!/bin/sh -e

. /etc/os-release
case "$ID" in
	"amzn")
		echo "Packaging..."
	;;
	"*")
		echo "An AWS Lambda function should only be packaged from an Amazon Linux to prevent broken shared library dependencies"
		exit
	;;
esac

FILES="apigwdyndns.py route53_dns.py ovh_dns.py"
TARGET="build"
DIST="dist"
DEST="$DIST/apigwdyndns.zip"

test -d .env || (echo "missing virtualenv environement."; exit 1)

test ! -d "$TARGET" || rm -rf $TARGET
test ! -d "$DIST" || rm -rf $DIST
mkdir $TARGET $DIST

cp -pdr \
	$(find .env/lib64/python3.6/site-packages/ -maxdepth 1 -not -path .env/lib64/python3.6/site-packages/) \
	$(find .env/lib/python3.6/site-packages/ -maxdepth 1 -not -path .env/lib/python3.6/site-packages/) \
	$(find .env/lib/python3.6/dist-packages/ -maxdepth 1 -not -path .env/lib/python3.6/dist-packages/ | grep -v 'pip$' | grep -v 'pip-' ) \
	"$TARGET/"

for F in $FILES; do
	cp -pd $F "$TARGET/"
done

rm -f "$DEST"
cd "$TARGET" && zip --recurse-paths -9 "../$DEST" ./
