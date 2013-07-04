# ACL Conversion script for Rundeck 1.3 to 1.5

This groovy script allows converting a set of Rundeck .aclpolicy files from the old XML-based 1.x format, to the new Yaml based format introduced in Rundeck 1.4.

The process involves running the groovy script and passing a directory containing the xml files (whose names end with `.aclpolicy`), and optionally passing the `rundeck-config.properties` file which contains the "mappedRoles" definitions.

# Usage

    groovy -cp src/groovy src/groovy/convert.groovy <outdir> <xmldir> [rundeck-config.properties] [options...]

`outdir`: the output directory to store the generated files

`xmldir`: the directory containing `*.aclpolicy` files in XML format

`rundeck-config.properties`: optional file containing the old mappedRoles definitions.  If unused, pass the string: `-`

These are the current `options`:

`-adhoc <authorizations>`:  a comma-separated list of authorizations to grant every generated file for 'adhoc' scripts.  The default is `read,run`, but if you do not want to grant adhoc 'run' authorization, you can specify `read` instead.


The script will do the following:

* load the "mappedRoles" definitions from the config file
    * these define some authorizations for user groups/roles
* process each XML file, and generate a Yaml file with the same name in an output directory.
    * The Yaml file will contain authorizations for the "group" or "username" used in the XML file.
    * If the XML file defines authorizations for a "group" (role), and the rundeck-config.properties file is defined, then the yaml file will combine the mappedRoles into its authorizations

The result should be a set of `*.aclpolicy` files that can be used in Rundeck 1.4 or later, and are as equivalent as possible to the input files.

# Test

A test script allows a test of the conversion and the expected output:

    $ sh test.sh
    + set -e
    + groovy -cp src/groovy src/groovy/convert.groovy test/out test/ test/rundeck-config.properties -adhoc read,run
    xmldir: /Users/greg/devel/rundeck-acl-conversion/test
    generate test/admin.aclpolicy
    wrote yaml to test/out/admin.aclpolicy
    generate test/dev_group.aclpolicy
    wrote yaml to test/out/dev_group.aclpolicy
    + cd test/out
    + result=0
    + for i in '*.aclpolicy'
    + diff -q admin.aclpolicy ../expected/admin.aclpolicy
    + for i in '*.aclpolicy'
    + diff -q dev_group.aclpolicy ../expected/dev_group.aclpolicy
