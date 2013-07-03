
@Grab(group='org.yaml', module='snakeyaml', version='1.9')
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.DumperOptions
import groovy.xml.*

/**
 * Converts a Rundeck 1.3 xml-based ACL policy file into the new Yaml format
 */
class ConvertACL{
    File file
    def xml
    def acldata
    Yaml yaml
    static Map defaultAllowAll=[
        resource:
            [allow('*')],//# allow read/create all kinds
        adhoc:
            [allow('*')],//# allow read/running/killing adhoc jobs
        job: 
            [allow('*')],// # allow read/write/delete/run/kill of all jobs
        node:
            [allow('*')],// # allow read/run for all nodes
    ]
    static Map defaultAllowRead=[
        resource:
            [allow('read')],//# allow read all kinds
        adhoc:
            [allow('read')],//# allow read adhoc jobs
        job: 
            [allow('read')],// # allow read of all jobs
        node:
            [allow('read')],// # allow read and run for all nodes
    ]
    static Map defaultAllowReadRun=[
        resource:
            [allow('read')],//# allow read all kinds
        adhoc:
            [allow('read','run')],//# allow read adhoc jobs
        job: 
            [allow('read','run')],// # allow read of all jobs
        node:
            [allow('read','run')],// # allow read and run for all nodes
    ]
    static Map defaultApplicationContext=[
        context:
            [application:'rundeck'],
        'for':
            [resource:[allow('read')]],
        by:
            [:]
    ]
    Map defaultFor
    Map options=[
        //automatically include application context in output document if true
        automaticApplicationContext:true,
        //define mapping from old Rundeck "mappedRoles", keyed by role, value is set of application roles
        roleMapping:[:]
    ]
    public ConvertACL(File file){
        this.file=file
        this.acldata=[]
        final DumperOptions dumperOptions = new DumperOptions();
        dumperOptions.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        yaml = new Yaml(dumperOptions);
        defaultFor=defaultAllowRead
    }
    public void convertTo(output){
        this.xml = new XmlParser().parse(file)
        generate()
        writeTo(output)
    }
    private String starToRegex(v){
        v=='*'?'.*':v
    }
    private Object actions(v){
        if(v=='*'){
            return v
        }else if(v.indexOf(',')>0){
            return v.split(',').collect{
                it.trim().replaceAll(/^workflow_/,'')
            }
        }
    }
    static Map allow(String...actions){
        [allow: Arrays.asList(actions)]
    }
    private void generate(){
        println "generate ${file}"
        def projectCtxs=[:]
        xml.policy.each{policy->
            def map=[:]
            map.description=policy.'@description'
            map.context=[project:starToRegex(policy.context.'@project'.text())]
            if(!projectCtxs[map.context.project]){
                projectCtxs[map.context.project]=[group:new HashSet(),user:new HashSet()]
            }

            map.by=[:]
            def groupRole=null
            if(policy.by.group.size()>0){
                map.by.group=policy.by.group.'@name'.text()
                projectCtxs[map.context.project].group<<map.by.group
                groupRole=map.by.group
            }else{
                map.by.username=policy.by.user.'@name'.text()
                projectCtxs[map.context.project].username<<map.by.user
            }

            def jobs=[]
            map.'for'=new HashMap(this.defaultFor)
            //determine mapped role authorizations for jobs ("workflows")
            def jobAuth=options.roleMapping[groupRole]?.findAll{it=~/^workflow_/}.collect{it.replaceAll(/^workflow_/,'')}
            //job authorizations
            policy.context.command.each{ auth->
                def joballow=actions(auth.'@actions')
                if(jobAuth && joballow!='*'){
                    joballow=new ArrayList(new HashSet([joballow].flatten()+jobAuth))
                }
                def match=[match:[:],allow: joballow]
                match.match.name=starToRegex(auth.'@job')
                match.match.group=starToRegex(auth.'@group')
                jobs<<match
            }

            if(jobs){
                map.'for'.job=jobs
            }


            acldata<<map
        }
        if(this.options.automaticApplicationContext){
            //add an application context to give access for the projects to the groups/users
            projectCtxs.each{project,ctxts->
                def app=new HashMap(defaultApplicationContext)
                app.'for'=new HashMap(app.'for') + [project:[
                    match:[
                        name: project
                    ],
                    allow:[
                        'read'
                    ]
                ]]
                //user admin
                if(options.roleMapping[groupRole]?.contains('user_admin')){
                    app.'for'.resource<<[
                        equals:[
                            kind:'user',
                        ],
                        allow:'admin'
                    ]
                }
                def newctxts = [:]
                def desc=""
                if(ctxts.group){
                    newctxts.group=new ArrayList(ctxts.group)
                    desc+="groups: "+ctxts.group.join(", ")
                }
                if(ctxts.username){
                    newctxts.username=new ArrayList(ctxts.username)
                    desc+="users: "+ctxts.username.join(", ")
                }
                app.by=newctxts
                app.description="Generated context for access to project ${project} for ${desc}".toString()
                acldata<<app
            }
        }
    }
    private void writeTo(output){
        output.withWriter { writer ->
            yaml.dumpAll(acldata.iterator(),writer)
        }
        println "wrote yaml to ${output}"
    }
}