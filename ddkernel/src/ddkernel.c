#ifndef __DD_KERNEL__
#define __DD_KERNEL__
#endif

#ifndef __DD_MODULE__
#define __DD_MODULE__
#endif

#include<linux/init.h>
#include<linux/kernel.h>
#include<linux/module.h>

#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/ip.h>
#include<linux/udp.h>
#include<linux/spinlock.h>



#define DNS_HEAD_LEN 		12
#define STR_IP(str, n) sprintf((str), "%u.%u.%u.%u", (n)  & 0xff, ((n)>> 8) & 0xff, ((n)>>16) & 0xff, ((n)>>24) & 0xff)
#define DNS_PORT 		53
#define UDP_HEAD_LEN 		8
#define DOMAIN_HASH_SIZE  	10000     //hash表大小
#define MAX_WARN_TIMES 		5000    //告警最大值
#define MIN_CANCLE_TIMES 	500      //接触预警阈值
#define CRC_MUL 		0x1021    /*生成多项式*/
#define TPDL_LEN 		21
#define DD_PROC_NAME 		"dd_domain_files"
#define MAX_HANDLE_BIND   	8000    //bind服务最大处理长度
#define PROC_MSG_LEN 		1024     //proc最长
#define TIME_FRAG_SEGME         8       //时间片分割
#define CMP_SCALE               0.5
#define MIN_RAT			0.2
#define DD_TEST_PROC 		"dd_test_info"

static struct hlist_head dd_domain_hlist[DOMAIN_HASH_SIZE];
static unsigned long one_time_frag = 0;
static unsigned long jf_time_frag  = 0;
static unsigned int  hlist_inst_flag = 1;
spinlock_t ddlist_spin_lock[DOMAIN_HASH_SIZE];
spinlock_t time_frag_lock = SPIN_LOCK_UNLOCKED;

typedef struct dns_domain_node{
	struct hlist_node hlist;
	unsigned int  crc;
	atomic_t  r_times;
	unsigned long t_frag;
	u8 dflag;
	u8 flag; 
	char * d_name;
}DDN;

static void call_to_user(char *d);
static void init_hash_size (void);
static void free_hash_size (void) ;
static void delete_node(int h,char *d);
static int  execute( const char *c);
static DDN * to_find_node( unsigned int crc , int hash) ;
static DDN * new_dns_info( unsigned int crc , int hash , char * d_name);
static ssize_t dd_proc_read (struct file * file,char *data,size_t len,loff_t *off);
static ssize_t dd_proc_write(struct file *file, const char *data,size_t len,loff_t *off);
static unsigned int cal_crc( unsigned char *ptr , unsigned char len) ;
static unsigned int trim( char *string ) ;
static unsigned int get_domain_name( const char* addr , char* urlbuff, int len);
static unsigned int hook_in_func ( unsigned int hooknum, struct sk_buff *skb , 
		const struct net_device *in, const struct net_device *out, 
		int (*okfn)(struct sk_buff *) );


atomic_t t_packet_times = ATOMIC_INIT(0);//数据包请求个数
atomic_t t_avail_times  = ATOMIC_INIT(0); //有效的请求次数
static char  proc_test_msg[1024]={};

//total times
atomic64_t all_times=ATOMIC64_INIT(0);
////anti domain times
atomic64_t anti_times=ATOMIC64_INIT(0);
////accept times
atomic64_t accept_times=ATOMIC64_INIT(0);
////limit times
atomic64_t limit_times=ATOMIC64_INIT(0);
unsigned int t_domain_numb =0; //总域名个数
unsigned int dd_guard_flag =0;
unsigned int dd_anyla_flag =0;
unsigned int avge_acce_times=0;
static struct nf_hook_ops dns_nfo;

static char *get_master_domain(char *domain){
	char *p_s, *p_e=NULL;
	char *p;
	int tag = 0, i;
	int len = strlen(domain) - 1;
	char top_domain[10]={0};
	char tpdl[TPDL_LEN][10] = { 
		".com.",
		".net.",
		".edu.",
		".gov.",
		".org.",
		".info.",
		".name.",
		".biz.", 
		".pro.",
		".aero.",
		".asia.",
		".cat.",
		".coop.",
		".int.",
		".jobs.",
		".mil.",
		".mobi.",
		".museum.",
		".tel.",
		".travel.",
		".xxx.",
	};

	p = domain;
	while(*p != '\0'){
		if((*p > 64) && (*p < 91))
			*p += 32;
		p ++;
	}
	p = domain;
	while(len > 0){
		if( *(p+len) == '.' ){
			tag ++;
			if (tag == 1)
				p_e = p + len;
			else if(tag == 2){
				p_s = p + len;
				break;
			}
		}
		len --;
	}

	if(tag == 2){
		len = p_e - p_s + 1;
		/* 长度不正常的直接定义为主域名*/
		if(len > 8)
			return(++p_s);
		if(len < 5)
			return(++p_s);
		strncpy(top_domain, p_s, len);
		tag = 0;
		for(i=0;i<TPDL_LEN;i++){
			if(strcmp(top_domain, tpdl[i]) == 0){
				tag = 1;
				break;
			}
		}
		/*找不到的话，p_s就是主域 */
		if(tag == 0)
			return(++p_s);
		/* 找到了，则需要往前找一个“.”作为主域 */
		else{

			p = p_s - 2;
			while(p >= domain){
				if( *p == '.')
					return(++p);
				p --;
			}
			p = domain;
		}
	}
	else
		p = domain;


	return(p);
}



static int execute(const char *string)
{
	int ret;
	char *envp[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/usr/sbin:/bin:/usr/local/bin:/usr/bin",
		NULL,
	};
	char *argv[] = {
		"/bin/bash",
		"-c",
		(char *)string,
		NULL,
	};

	if ((ret = call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT)) != 0) {
		printk(KERN_ERR "run user application failed %s: %d/n", string, ret);
	}

	return ret;
}

static void call_to_user(char *domain_name) 
{
	int ret = 0;
	char cmd[256];

        memset (cmd , 0 ,sizeof(cmd));
        sprintf(cmd ,"/usr/local/bin/alert_mail.sh  %s" , domain_name);
        ret = execute(cmd);

	return ;
}



static unsigned int get_domain_name(const char* addr, char* urlbuff, int len) 
{
	const char * p = addr;
	int pos = 0;

	while(p && (*p > 0)) {
		if(*p > len) {
			break;
		}
		strncpy(urlbuff+ pos, p + 1, *p);
		pos +=  *p;
		urlbuff[pos] = '.';
		pos++;
		len -= (*p + 1);
		p += (*p + 1);
	}
	if(pos > 0) 
		urlbuff[pos - 1] ='\0';

	return pos;
}

static void init_hash_size ( void ) 
{
	unsigned int i;

	for( i = 0 ; i< DOMAIN_HASH_SIZE ; i++)
	{
		INIT_HLIST_HEAD( &dd_domain_hlist[i] );
		spin_lock_init ( &ddlist_spin_lock[i] );
	}
	spin_lock_init( &time_frag_lock );

	return;
}

static void free_hash_size(void) 
{
	unsigned int i = 0;
	struct hlist_node *pos,*n;

	DDN* node;
	for( i = 0 ; i < DOMAIN_HASH_SIZE ; i++ ) {
		spin_lock_bh(&ddlist_spin_lock[i]);
		hlist_for_each_safe(pos,n,&dd_domain_hlist[i]){
			node = hlist_entry(pos,DDN,hlist);
			hlist_del(pos);
			if ( node->d_name)
				kfree(node->d_name);
			if (node)
				kfree(node);
		}
		spin_unlock_bh(&ddlist_spin_lock[i]);
	}

	return ;
}

static  unsigned int cal_crc(unsigned char *ptr , unsigned char len) 
{
	unsigned char i;
	unsigned int crc=0;

	while(len-- != 0) {
		for( i = 0x80; i != 0; i/=2) {
			if((crc&0x8000) != 0) {crc*=2; crc^=CRC_MUL;}   /* 余式CRC乘以2再求CRC  */
			else crc*=2;
			if((*ptr&i)!=0) crc^=CRC_MUL;                /* 再加上本位的CRC */
		}
		ptr++;
	}

	return(crc);
}



static DDN * to_find_node(  unsigned int crc ,int hash) 
{
	struct hlist_node *pos;

	DDN *ddn,*n = NULL;
	hlist_for_each_entry ( ddn , pos , &dd_domain_hlist[hash] , hlist ){
		n = hlist_entry(pos,DDN,hlist);
		if( n->crc == crc ){
			break;
		}
	}

	return n;
}

static DDN *  new_dns_info( unsigned int crc ,int hash , char * d_name) 
{
	DDN * ddn ;
	char *c_name;

	c_name = (char *) kmalloc( strlen( d_name )+ 1 , GFP_ATOMIC );
	if ( !c_name ){
		return NULL;
	}
	memset ( c_name , 0 , sizeof (strlen(d_name)+1));
	memcpy ( c_name , d_name , strlen(d_name) );
	ddn = (DDN *)kmalloc(sizeof(DDN)+1, GFP_ATOMIC );
	if ( !ddn ){
		return NULL;
	}
	memset ( ddn , 0 , sizeof (DDN)+1);
	ddn->crc    = crc;
	ddn->d_name = c_name;

	spin_lock_bh(&ddlist_spin_lock[hash]);
	hlist_add_head(&ddn->hlist, &dd_domain_hlist[hash]);
	spin_unlock_bh(&ddlist_spin_lock[hash]);
	printk("insert into domain_name:%s\n",d_name);

	return ddn;
}


static unsigned int hook_in_func ( unsigned int hooknum, struct sk_buff *skb , 
		const struct net_device *in, const struct net_device *out, 
		int (*okfn)(struct sk_buff *) )
{
	struct sk_buff* sb =skb;
	struct udphdr * udph;
	struct iphdr  * iph  = ip_hdr(sb);
	unsigned long tmp_times;
	char s_url[1024] = {0};
	char * udp_data;
	char * dm_name;
	u_int16_t src_port, dst_port;
	u_int16_t udp_len = 0;
	u_int8_t flag;


	if(iph->protocol == IPPROTO_UDP){
		udph     = (struct udphdr*)(sb->data+(iph->ihl*4));
		src_port = ntohs(udph->source);
		dst_port = ntohs(udph->dest);
		udp_len  = ntohs(udph->len) - UDP_HEAD_LEN;
		if(udp_len <= DNS_HEAD_LEN) {
			return NF_DROP;
		}
		if(dst_port != DNS_PORT)
			return NF_ACCEPT;
			
		/* get to start point of udp data*/
		udp_data = (unsigned char*)(udph+ 1);
		flag     = ((u_int8_t)udp_data[2]) & 8;
		//flag:1 response,flag:0 query
		if( flag )
			return NF_ACCEPT;

		jf_time_frag = jiffies >> TIME_FRAG_SEGME;

		//判断是否在同一个时间片上
		if(one_time_frag != jf_time_frag){
			spin_lock_bh( &time_frag_lock );
			if(one_time_frag != jf_time_frag){
				one_time_frag  = jf_time_frag;

				if(atomic_read(&t_packet_times) >= MAX_WARN_TIMES){
					dd_guard_flag = 1;
					if( atomic_read(&t_avail_times) > MAX_WARN_TIMES ){
						dd_anyla_flag = 1;
						printk("defense analysis enable!\n");
					} else{
						dd_anyla_flag = 0;
						printk("defense analysis disable!\n");
					}
				}else if(atomic_read(&t_packet_times) < MIN_CANCLE_TIMES) {
					dd_guard_flag = 0;
					dd_anyla_flag = 0;
				}

				if(t_domain_numb == 0)
					avge_acce_times = 0;	
				else{	
					avge_acce_times = 20*(atomic_read(&t_packet_times)/t_domain_numb );
				        tmp_times = atomic_read(&t_packet_times) * CMP_SCALE;
                                        if ( tmp_times < avge_acce_times){
                                                avge_acce_times = tmp_times;
					}
					if (avge_acce_times < MAX_WARN_TIMES * MIN_RAT)
						avge_acce_times=MAX_WARN_TIMES*MIN_RAT;
					
				}

				printk("num=%d times=%d\n", t_domain_numb, avge_acce_times);

				t_domain_numb = 0;
				atomic_set( &t_packet_times, 0);
				atomic_set( &t_avail_times , 0);
			}
			spin_unlock_bh( &time_frag_lock );
		}
		atomic_inc(&t_packet_times);
		atomic64_inc(&all_times);
		if( dd_guard_flag ){
			int hash;
			unsigned int crc=0;
			DDN *n = NULL;
			get_domain_name(udp_data + DNS_HEAD_LEN, s_url, udp_len - DNS_HEAD_LEN);
			dm_name = get_master_domain(s_url);
			crc 	= cal_crc ( dm_name , strlen(dm_name));
			hash 	=  crc % DOMAIN_HASH_SIZE;

			//维护主域名列表 ,包括查找和新建主域名插入列表 
			n 	= to_find_node(crc, hash);

			//是否要插入列表需要一个策略记录（是否允许插入) [新建或丢弃] hlist_inst_flag
			if(!hlist_inst_flag && !n){
				printk("new node faild insert flag is 0 ,return drop!\n");
				return NF_DROP;
			}
			if( !n ) 
				n = new_dns_info( crc , hash , dm_name );
			if( !n ) {
				printk("new node faild return accept!\n");
				return NF_ACCEPT;
			}

			//对于当前主域名时间片切换分析,当前时间片主域名个数加一，并且更新时间。
			if(n->t_frag != jf_time_frag){
				spin_lock_bh(&time_frag_lock);
				if( n->t_frag != jf_time_frag){
					n->t_frag  = jf_time_frag;

					//进入分析状态
					if( dd_anyla_flag && !n->dflag && atomic_read(&n->r_times) > avge_acce_times){
						n->dflag=1;

						//通知用户层程序
						call_to_user(n->d_name);
						printk("mail alarm enable\n");
						
					}
					atomic_set(&n->r_times,0);
					t_domain_numb ++;
				}
				spin_unlock_bh(&time_frag_lock);
			}
			if( n->dflag ){
				atomic64_inc(&anti_times);
				return NF_DROP;
			}

			atomic_inc(&n->r_times);
		}


		if(atomic_read( &t_avail_times) > MAX_HANDLE_BIND){
			atomic64_inc(&limit_times);
			return NF_DROP;
		}

		atomic_inc( &t_avail_times);
		atomic64_inc(&accept_times);
	}

	return NF_ACCEPT;
}

static unsigned int trim( char *string ) 
{
	int i, len;
	char tmp[1024];

	memset(tmp, 0, 1024);
	len = strlen( string );

	for(i = len -1; i >= 0; i--)
	{
		if (string[i] == 0x20 || string[i] == '\t')
			string[i] = '\0';
		else
			break;
	}
	memcpy (tmp,string,strlen(string));
	for(i = 0; i < len; i++)
	{
		if(tmp[i] != 0x20 && tmp[i] != '\t')
		{
			strcpy( string, tmp+i );
			return strlen( string );
		}
	}
	string[0] = 0;

	return 0;
}


static void delete_node(int hash ,char *d_name)
{
        struct hlist_node *pos,*n;
        DDN* node;

        printk("delete domainname:%s\n",d_name);
        spin_lock_bh(&ddlist_spin_lock[hash]);
        hlist_for_each_safe(pos,n,&dd_domain_hlist[hash]){
                node = hlist_entry(pos,DDN,hlist);
                if ( memcmp(node->d_name , d_name , strlen(d_name))==0){
                        hlist_del(pos);
                        if ( node->d_name)
                                kfree(node->d_name);
                        if (node)
                                kfree(node);
                }
        }
        spin_unlock_bh(&ddlist_spin_lock[hash]);

        return;
}

static struct proc_dir_entry * ddproc_entry = NULL;
static ssize_t dd_proc_read(struct file * file,char *data,size_t len,loff_t *off) {
	char proc_msg[PROC_MSG_LEN]={"Anquanbao.com\n"};
	if(*off > 0)
		return 0;
	if(copy_to_user( data , proc_msg , strlen(proc_msg)))
		return -EFAULT;
	*off += strlen( proc_msg );


	return strlen( proc_msg );
}

static ssize_t test_read(struct file * file,char *data,size_t len,loff_t *off) {
	if(*off > 0)
		return 0;
	sprintf(proc_test_msg ,"all-times:%ld	anti-times:%ld	limit-(bind)-times:%ld	accept-times:%ld\n",
				atomic64_read(&all_times),atomic64_read(&anti_times),atomic64_read(&limit_times),atomic64_read(&accept_times));
	if(copy_to_user( data , proc_test_msg , strlen(proc_test_msg)))
		return -EFAULT;
	*off += strlen( proc_test_msg );

	return strlen( proc_test_msg );
}
static ssize_t dd_proc_write(struct file *file, const char *data,size_t len,loff_t *off)
{

	char proc_msg[PROC_MSG_LEN]={"Anquanbao.com\n"};
	int tag=2;
	char * dm_name,*str;
	unsigned int crc;
	int hash;
	DDN *n = NULL;

	if(copy_from_user( proc_msg , (void*)data , len) )
		return -EFAULT;
	proc_msg[len]='\0';
	trim(proc_msg);
	if( !strlen(proc_msg) )
		return len;

	if( memcmp(proc_msg,"A_",2) == 0){
		str = proc_msg+2;	
		tag=0;
	}else if (memcmp (proc_msg ,"D_",2)==0){
		str = proc_msg+2;
		tag=1;
	}	
	
	if (tag < 2 ){
		dm_name = get_master_domain(str);
		crc = cal_crc ( dm_name , strlen ( dm_name) );
		hash = crc % DOMAIN_HASH_SIZE;
		n = to_find_node( crc , hash );
		if ( tag == 0 && !n && hlist_inst_flag){
			n = new_dns_info( crc , hash , dm_name );
		}else if ( tag == 1 && n){
			delete_node(hash,dm_name);
		}
	}

	return len;
}

static struct file_operations dd_proc_ops = {
	.owner = THIS_MODULE,
	.read  = dd_proc_read,
	.write = dd_proc_write,
};


static struct file_operations test_ops = {
	.owner = THIS_MODULE,
	.read  = test_read,
};
static int init_test_proc(void){
	ddproc_entry = create_proc_entry(DD_TEST_PROC,0666,NULL);
	if(!ddproc_entry){
		printk(KERN_ERR "can't create /proc/dd_domain_files!\n");
		return -EFAULT;
	}
	ddproc_entry->proc_fops = &test_ops;

	return 0;
}
static int __init _dd_kernel_init(void) {

	init_hash_size();
	init_test_proc();
	dns_nfo.hook    = hook_in_func;
	dns_nfo.hooknum = NF_INET_LOCAL_IN;
	dns_nfo.pf      = PF_INET;
	dns_nfo.priority= NF_IP_PRI_FIRST;
	nf_register_hook( &dns_nfo );
	ddproc_entry = create_proc_entry(DD_PROC_NAME,0666,NULL);
	if(!ddproc_entry){
		printk(KERN_ERR "can't create /proc/dd_domain_files!\n");
		return -EFAULT;
	}
	ddproc_entry->proc_fops = &dd_proc_ops ;
	printk("dd_kernel load finish!\n");

	return 0;
}


static void __exit _dd_kernel_exit(void)
{
	free_hash_size ();
	nf_unregister_hook( &dns_nfo );
	remove_proc_entry ( DD_PROC_NAME , NULL );
	remove_proc_entry ( DD_TEST_PROC , NULL );
	printk( KERN_INFO "dd_kernel unload finish!\n");

	return;
}
module_init( _dd_kernel_init );
module_exit( _dd_kernel_exit );

MODULE_VERSION("V1.0");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anquanbao.com");
