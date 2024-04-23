#!/bin/sh

if ! git clone https://github.com/partior-3p/PEEPS.git
then
  cd PEEPS
  git reset --hard HEAD
  git pull origin master
else
  cd PEEPS
fi

./gradlew --no-daemon endToEndTest

