#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <sys/types.h>
#include <unistd.h>

#define NETLINK_TEST 25
#define MAX_PAYLOAD_SIZE 10240 // maximum payload size
void substr(char *dest,const char *src,int start,int cnt)
{
    strncpy(dest,src+start,cnt);
    dest[cnt]=0;
}

int main(int argc, char* argv[])
{
    int state;
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    int sock_fd, retval;
    int state_smg = 0;
    char command[5]="c10";

    // Create a socket
    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_TEST);
    if(sock_fd == -1) {
        printf("error getting socket: %s", strerror(errno));
        return -1;
    }

    // To prepare binding
    memset(&msg,0,sizeof(msg));
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    src_addr.nl_groups = 0;

    retval = bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
    if(retval < 0) {
        printf("bind failed: %s", strerror(errno));
        close(sock_fd);
        return -1;
    }
    printf("user pid %d\n", getpid());

    // To prepare recvmsg
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD_SIZE));
    if(!nlh) {
        printf("malloc nlmsghdr error!\n");
        close(sock_fd);
        return -1;
    }

    memset(&dest_addr,0,sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;


    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD_SIZE);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    //to send command
    if(strncmp(argv[1],"-c",2)==0) {
        if(strlen(argv[1])==2) {
            strcpy(NLMSG_DATA(nlh), "c");
        } else {
            char p[strlen(argv[1])-1];
            substr(p,argv[1],1,strlen(argv[1])-1);
            strcpy(NLMSG_DATA(nlh), p);
        }
    } else if(strncmp(argv[1],"-s",2)==0) {
        if(strlen(argv[1])==2) {
            strcpy(NLMSG_DATA(nlh), "s");
        } else {
            char p[strlen(argv[1])-1];
            substr(p,argv[1],1,strlen(argv[1])-1);
            strcpy(NLMSG_DATA(nlh), p);
        }
    } else if(strncmp(argv[1],"-p",2)==0) {
        if(strlen(argv[1])==2) {
            strcpy(NLMSG_DATA(nlh), "p");
        } else {
            char p[strlen(argv[1])-1];
            substr(p,argv[1],1,strlen(argv[1])-1);
            strcpy(NLMSG_DATA(nlh), p);
        }
    }



    iov.iov_base = (void *)nlh;
    iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD_SIZE);

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    state_smg = sendmsg(sock_fd, &msg, 0);
    if(state_smg == -1) {
        printf("get error sendmsg = %s\n",strerror(errno));
    }

    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD_SIZE));
    printf("waiting received!\n");
    // Read message from kernel
    state = recvmsg(sock_fd, &msg, 0);
    if(state < 0) {
        printf("recvmsg state < 1");
    }
    printf("%s\n",(char *) NLMSG_DATA(nlh));
    close(sock_fd);

    return 0;
}