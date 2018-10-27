#include <linux/init.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/list.h>
#include <linux/string.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>

#define NETLINK_TEST 31
#define MAX_PAYLOAD_SIZE 10000

char msg[10000];
struct sock *nl_sk = NULL;
pid_t pid = 1;
int time =0;
module_param(pid,int,0644);

void pstree(struct task_struct* task,int i)
{
    i++;
    int j;
    struct list_head *children_tasks;
    children_tasks = &(task->children);
    list_for_each(children_tasks,&(task->children)) {
        struct task_struct *child_task;
        child_task = list_entry(children_tasks,struct task_struct,sibling);
        j=i-1;
        while(j!=0) {
            sprintf(msg+ strlen(msg),"\t");
            j--;
        }
        printk("%s(%d)",child_task->comm,child_task->pid);
        sprintf(msg+ strlen(msg),"\t%s(%d)\n", child_task->comm,child_task->pid);
        pstree(child_task,i);
    }
}

void substr(char *dest,const char *src,int start,int cnt)
{
    strncpy(dest,src+start,cnt);
    dest[cnt]=0;
}

void sendnlmsg(int pid)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh,*h;

    //  memset(msg,0,sizeof(msg));
    if(!nl_sk) {
        return;
    }
    skb = nlmsg_new(MAX_PAYLOAD_SIZE, GFP_KERNEL);
    if(!skb) {
        printk(KERN_ERR "nlmsg_new error!\n");
    }
    nlh = nlmsg_put(skb, 0, 0, 0, MAX_PAYLOAD_SIZE, 0);

    memcpy(NLMSG_DATA(nlh), msg, sizeof(msg));
    // strcpy(NLMSG_DATA(nlh),msg);
    printk("Send message '%s'.\n",(char *)NLMSG_DATA(nlh));

    netlink_unicast(nl_sk, skb, pid, MSG_DONTWAIT);
}

void nl_data_ready(struct sk_buff *__skb)
{
    msg[10000]="";
    pid_t command_pid;
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    char str[100];
    int i= 0;
    // get current pid
    struct pid* cur_pid = find_get_pid(current->pid);
    struct task_struct* cur_task = pid_task(cur_pid, PIDTYPE_PID);
    struct task_struct *p;
    struct list_head *pp = NULL;
    struct task_struct *psibling;
    struct task_struct *pparent,*pchildren;
    printk("current pid level: %d\n",cur_pid->numbers[cur_pid->level].nr);
    printk("current pid%d\n", current->pid);
    // get current tasks
    printk("current task piority: %d\n",cur_task->prio);
    printk("current task pid: %d\n",cur_task->pid);
    printk("current task name: %s\n",cur_task->comm);

    skb = skb_get (__skb);
    if(skb->len >= NLMSG_SPACE(0)) {
        nlh = nlmsg_hdr(skb);
        memcpy(str, NLMSG_DATA(nlh), sizeof(str));
        printk("Message received:%c \n",str[0]);

        //parent
        if(str[0]=='p') {
            char pstr[strlen(str)-1],*end;
            substr(pstr,str,1,strlen(str)-1);
            command_pid = simple_strtoul(pstr,&end,10);
            p = pid_task(find_vpid(command_pid), PIDTYPE_PID);
            if(p!=NULL) {
                memset(msg,0,sizeof(msg));
                //  sprintf(msg,"%s(%d)\n", p->comm, p->pid);
                do {
                    pparent = p;
                    printk("%s(%d)\n",  p->comm,p->pid);
                    sprintf(msg+ strlen(msg),"%s(%d) &", pparent->comm,pparent->pid);
                    p =p->parent;
                } while(pparent->pid!=0);
            } else {
                memset(msg,0,sizeof(msg));
            }
        }
        //siblings
        else if(str[0]=='s') {
            char pstr[strlen(str)-1],*end;
            substr(pstr,str,1,strlen(str)-1);
            command_pid = simple_strtoul(pstr,&end,10);
            p = pid_task(find_vpid(command_pid), PIDTYPE_PID);
            if(p!=NULL) {
                memset(msg,0,sizeof(msg));
                //  sprintf(msg,"%s(%d)\n", p->comm, p->pid);
                list_for_each(pp, &p->parent->children) {
                    psibling = list_entry(pp, struct task_struct, sibling);
                    printk("%s(%d)\n",  psibling->comm,psibling->pid);
                    if(psibling->pid!=p->pid) {
                        sprintf(msg+ strlen(msg),"%s(%d)\n",  psibling->comm,psibling->pid);
                    }

                }
            } else {
                memset(msg,0,sizeof(msg));
            }
        }
        //children
        else if(str[0]=='c') {
            char pstr[strlen(str)-1],*end;
            substr(pstr,str,1,strlen(str)-1);
            command_pid = simple_strtoul(pstr,&end,10);
            p = pid_task(find_vpid(command_pid), PIDTYPE_PID);
            if(p!=NULL) {
                memset(msg,0,sizeof(msg));
                sprintf(msg,"%s(%d)\n", p->comm, p->pid);
                pstree(p,0);


            } else {
                memset(msg,0,sizeof(msg));
            }
        }
        printk("%s",msg);
        sendnlmsg(nlh->nlmsg_pid);

        kfree_skb(skb);
    }
}

static int netlink_unicast_init(void)
{
    struct netlink_kernel_cfg netlink_kerncfg = {
        .input = nl_data_ready,
    };
    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, &netlink_kerncfg);
    if(!nl_sk) {
        printk(KERN_ERR "netlink_unicast_init: Create netlink socket error.\n");
        return -1;
    }
    printk("netlink_unicast_init: Create netlink socket ok.\n");
    return 0;
}
static void netlink_unicast_exit(void)
{
    if(nl_sk != NULL) {
        sock_release(nl_sk->sk_socket);
    }
    printk("netlink_unicast_exit!\n");
}
module_init(netlink_unicast_init);
module_exit(netlink_unicast_exit);

MODULE_LICENSE("GPL");