#!/usr/bin/env groovy

//This is a groovy script to convert Rundeck 1.3 XML based ACL Policy files, combined with the "mapped roles" from
//the rundeck-config.properties file
//into the Rundeck 1.4+ Yaml ACL Policy files


if(args.size() < 2){
    System.err.println("Usage: convert <outputdir> <xmlinputdir> [rundeck-config.properties] [options...]")
    System.err.println("options include:")
    System.err.println("\t-adhoc <defaults> : defaults is a comma-separated list of allowed authorization for adhoc")
    System.exit(1)
}

def outputdir = new File(args[0])
def xmldir = new File(args[1])
def configprops=null
if(args.length>2 && args[2]!='-'){
    configprops=new Properties()
    new File(args[2]).withInputStream { 
        configprops.load(it)
    }
}

def options=[:]
def adhocAllow=[]
if(args.length>3){
    for(int i=3;i<args.length;i++){
        switch(args[i]) {
            case '-adhoc':
                adhocAllow=args[i+1].split(',')
            break
        }
    }
    if(adhocAllow){
        options.adhocDefault=adhocAllow
    }
}

println "xmldir: ${xmldir.absolutePath}"
def xmlfiles = xmldir.listFiles().findAll{(it.name=~/\.(aclpolicy)$/)}

//println "xml files: ${xmlfiles}"
//println "configprops: ${configprops}"

//convert mapped roles to a set of options for particular groups to apply at conversion time

def MROLES_STRING='mappedRoles.'
def mappedRoles=[:]
configprops.each{k,v->
    if(k.startsWith(MROLES_STRING)){
        mappedRoles[k.substring(MROLES_STRING.size())]=v.split(',').collect{it.trim()}
    }
}

//invert map
def rolesMapped=[:]
mappedRoles.each{k,v->
    v.each{role->
        if(!rolesMapped[role]){
            rolesMapped[role]=new HashSet()
        }
        rolesMapped[role]<<k
    }
}
//println "mapped: ${rolesMapped}"

//return
xmlfiles.each{file->
    def convert=new ConvertACL(file)
    convert.options.putAll(options)
    convert.options.roleMapping=rolesMapped
    def outfile = new File(outputdir,file.name)
    convert.convertTo(outfile)
}