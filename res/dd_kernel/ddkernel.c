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
#include<linux/time.h>



#define DNS_HEAD_LEN 		12
#define STR_IP(str, n) sprintf((str), "%u.%u.%u.%u", (n)  & 0xff, ((n)>> 8) & 0xff, ((n)>>16) & 0xff, ((n)>>24) & 0xff)
#define DNS_PORT 		53
#define UDP_HEAD_LEN 		8
#define MDN_HASH_SIZE  	10000     //hash表大小
#define MAX_ALERT_VALUE 		5000    //告警最大值
#define CANCLE_ALERT_VALUE 	500      //接触预警阈值
#define CRC_MUL 		0x1021    /*生成多项式*/
#define TPDL_LEN 		21
#define MAX_HANDLE_BIND   	8000    //bind服务最大处理长度
#define PROC_MSG_LEN 		1024     //proc最长
#define TIME_FRAG_SEGME         10       //时间片分割
#define CMP_SCALE               0.5
#define IPADDR_QUERY_TIMES	50
#define MDN_QUERY_TIMES 		1000   //主域查询次数
#define PAN_SCALE		0.8

//ip地址范围 

#define DD_TEST_PROC            "dd_test_info"

#define IPNODE_HASH_SIZE	10001
#define DD_MDMN_PROC 		"dd_mdname_info"
#define DD_IPADDR_PROC 		"dd_ipaddr_info"
#define DD_SUBDMN_PROC 		"dd_subdmn_info"

static struct hlist_head dd_mdn_hlist[MDN_HASH_SIZE];
static struct hlist_head dd_ipinfo_hlist[IPNODE_HASH_SIZE];
static struct hlist_head dd_subdmn_hlist[MDN_HASH_SIZE];


//total times
atomic64_t all_times=ATOMIC64_INIT(0);
//////anti domain times
atomic64_t anti_times=ATOMIC64_INIT(0);
//////accept times
atomic64_t accept_times=ATOMIC64_INIT(0);
//////limit times
atomic64_t limit_times=ATOMIC64_INIT(0);

static unsigned long one_time_frag = 0;
static unsigned long jf_time_frag  = 0;
static unsigned int  hlist_inst_flag = 1;
spinlock_t ddmdn_spin_lock[MDN_HASH_SIZE];
spinlock_t ddip_spin_lock[IPNODE_HASH_SIZE];
spinlock_t ddsubdn_spin_lock[MDN_HASH_SIZE];
spinlock_t mdn_timeslice = SPIN_LOCK_UNLOCKED;
spinlock_t ip_timeslice  = SPIN_LOCK_UNLOCKED;
static char  proc_test_msg[1024]={};

static struct proc_dir_entry * mdn_proc_entry   = NULL;
static struct proc_dir_entry * test_proc_entry   = NULL;
static struct proc_dir_entry * ddproc_ip_entry= NULL;
static struct proc_dir_entry * ddproc_dn_entry= NULL;

typedef struct dns_domain_node{
	struct hlist_node hlist;
	unsigned int  crc;
	unsigned long last_time; //recv last time
	unsigned long anti_time; //anti_flag time
	atomic_t  times;	//recv all quest times in one frag time 
	atomic_t  pan_times;    //recv pan-domain quest times 
	u8 anti_flag;
	u8 pan_flag; 
	char * d_name;
}MDN;

typedef struct ipinfo_list_node{
	struct hlist_node hlist;
	unsigned int  crc;
	unsigned long last_time;
	atomic_t  times;
}IPN;

typedef struct dninfo_list_node{
	struct hlist_node hlist;
	unsigned int  crc;
}SDMN;

static void call_to_user(char *d);
static void init_mdmn_hash (void);
static void free_mdmn_hash(void) ;
static void delete_node(int h,char *d);
static int  execute( const char *c);
static MDN * find_mdn_node( unsigned int crc , int hash) ;
static MDN * new_mdn_node( unsigned int crc , int hash , char * d_name);
static ssize_t mdn_proc_write(struct file *file, const char *data,size_t len,loff_t *off);
static unsigned int cal_crc( unsigned char *ptr , unsigned char len) ;
static unsigned int trim( char *string ) ;
static unsigned int get_domain_name( const char* addr , char* urlbuff, int len);
static unsigned int hook_func ( unsigned int hooknum, struct sk_buff *skb , 
		const struct net_device *in, const struct net_device *out, 
		int (*okfn)(struct sk_buff *) );


static ssize_t ipinfo_proc_write(struct file *file, const char *data,size_t len,loff_t *off);
static ssize_t subdn_proc_write(struct file *file, const char *data,size_t len,loff_t *off);

atomic_t t_packet_times = ATOMIC_INIT(0);//数据包请求个数
atomic_t t_avail_times  = ATOMIC_INIT(0); //有效的请求次数


unsigned int t_domain_numb =0; //总域名个数
unsigned int dd_guard_flag =0;
unsigned long dd_guard_time;
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
		"PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/bin",
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
	sprintf(cmd ,"/usr/local/bin/alert_mail.sh  %s\n" , domain_name);
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

static void init_mdmn_hash( void ) 
{
	unsigned int i;

	for( i = 0 ; i< MDN_HASH_SIZE ; i++)
	{
		INIT_HLIST_HEAD( &dd_mdn_hlist[i] );
		spin_lock_init ( &ddmdn_spin_lock[i] );
	}
	spin_lock_init( &mdn_timeslice);
	spin_lock_init( &ip_timeslice);
}
static void init_ipinfo_hash( void ) 
{
	unsigned int i;

	for( i=0 ; i< IPNODE_HASH_SIZE;i++){
		INIT_HLIST_HEAD( &dd_ipinfo_hlist[i] );
		spin_lock_init ( &ddip_spin_lock[i] );
	}
}
static void init_subdn_hash( void ) 
{
	unsigned int i;

	for( i=0 ; i< MDN_HASH_SIZE ;i++){
		INIT_HLIST_HEAD( &dd_subdmn_hlist[i] );
		spin_lock_init ( &ddsubdn_spin_lock[i] );
	}
	return;
}



static void free_ipinfo_hash(void)
{
	unsigned int i;
	struct hlist_node *pos,*n;
	IPN * ipinfo;	

	for(i=0; i< IPNODE_HASH_SIZE; i++){
		ipinfo = NULL;
		if(!hlist_empty(&dd_ipinfo_hlist[i])){
			hlist_for_each_entry_safe(ipinfo, pos, n, &dd_ipinfo_hlist[i], hlist){
				hlist_del(&ipinfo->hlist);
				if (ipinfo)
					kfree(ipinfo);
			}
		}
	}
}

static void free_subdn_hash(void)
{
	unsigned int i;
	struct hlist_node *pos,*n;
	SDMN * dninfo;

	for(i=0; i<MDN_HASH_SIZE; i++){
		dninfo = NULL;
		if(!hlist_empty(&dd_subdmn_hlist[i])){
			hlist_for_each_entry_safe(dninfo, pos, n, &dd_subdmn_hlist[i], hlist){
				hlist_del(&dninfo->hlist);
				if (dninfo)
					kfree(dninfo);
			}
		}
	}
}

static void free_mdmn_hash(void) 
{
	unsigned int i = 0;
	struct hlist_node *pos,*n;

	MDN* node;
	for( i = 0 ; i < MDN_HASH_SIZE ; i++ ) {
		spin_lock_bh(&ddmdn_spin_lock[i]);
		if(!hlist_empty(&dd_mdn_hlist[i])){
			hlist_for_each_safe(pos,n,&dd_mdn_hlist[i]){
				node = hlist_entry(pos,MDN,hlist);
				hlist_del(pos);
				if ( node->d_name)
					kfree(node->d_name);
				if (node)
					kfree(node);
			}
		}
		spin_unlock_bh(&ddmdn_spin_lock[i]);
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



static MDN * find_mdn_node(  unsigned int crc ,int hash) 
{
	struct hlist_node *pos;
	MDN *ddn,*n = NULL;


	hlist_for_each_entry ( ddn , pos , &dd_mdn_hlist[hash] , hlist ){
		n = hlist_entry(pos,MDN,hlist);
		if( n->crc == crc ){
			break;
		}
	}

	return n;
}

static IPN *  new_ipinfo_node( unsigned int crc ,int hash , char * ip)
{
	IPN * ipn ;

	ipn = (IPN *)kmalloc(sizeof(IPN) + 1, GFP_ATOMIC );
	if ( !ipn ){
		return NULL;
	}
	memset ( ipn , 0 , sizeof (IPN) + 1);
	ipn->crc= crc;

	spin_lock_bh(&ddip_spin_lock[hash]);
	hlist_add_head(&ipn->hlist, &dd_ipinfo_hlist[hash]);
	spin_unlock_bh(&ddip_spin_lock[hash]);

	return ipn;
}

static SDMN *  new_subdn_node( unsigned int crc ,int hash )
{
	SDMN * n ;

	n = (SDMN *)kmalloc(sizeof(SDMN)+1, GFP_ATOMIC );
	if ( !n ){
		return NULL;
	}
	n->crc= crc;

	spin_lock_bh(&ddsubdn_spin_lock[hash]);
	hlist_add_head(&n->hlist, &dd_subdmn_hlist[hash]);
	spin_unlock_bh(&ddsubdn_spin_lock[hash]);

	return n;
}

static IPN * find_to_ipnode(  unsigned int crc ,int hash) 
{
	struct hlist_node *pos,*n;
	IPN *ipn ,*n1= NULL;

	spin_lock_bh(&ddip_spin_lock[hash]);
		hlist_for_each_entry_safe(ipn, pos, n, &dd_ipinfo_hlist[hash], hlist){
				if (ipn->crc == crc){
					n1= ipn;				
				}
		}
	spin_unlock_bh(&ddip_spin_lock[hash]);
#if 0

	hlist_for_each_entry ( ipn , pos , &dd_ipinfo_hlist[hash] , hlist ){
		n = hlist_entry(pos,IPN,hlist);
		if (n)
			if( n->crc == crc ){
				break;
			}
	}
#endif

	return n1;
}

static SDMN *find_to_sdmn(char *req )
{
	struct hlist_node *pos;
	unsigned int crc;
	int hash;
	SDMN *fn,*n = NULL;
	crc 	= cal_crc ( req , strlen(req));
	hash 	=  crc % MDN_HASH_SIZE;
	hlist_for_each_entry ( fn , pos , &dd_subdmn_hlist[hash] , hlist ){
		n = hlist_entry(pos,SDMN,hlist);
		if( n->crc == crc ){
			break;
		}
	}

	return n;
}


static SDMN * find_to_subdn(  unsigned int crc ,int hash)
{
	struct hlist_node *pos;
	SDMN *fn,*n = NULL;
	hlist_for_each_entry ( fn , pos , &dd_subdmn_hlist[hash] , hlist ){
		n = hlist_entry(pos,SDMN,hlist);
		if( n->crc == crc ){
			break;
		}
	}

	return n;
}
static MDN *  proc_new_mdn_node( unsigned int crc ,int hash , char * d_name) 
{
	MDN * mdn =NULL;
	char *c_name=NULL;
	int len=0;

	len = strlen( d_name ) +1;
	c_name = (char *) kmalloc( len , GFP_ATOMIC );
	if ( !c_name ){
		return NULL;
	}
	memset ( c_name , 0 , len );
	memcpy ( c_name , d_name , strlen(d_name) );

	mdn = (MDN *)kmalloc(sizeof(MDN)+1, GFP_ATOMIC );
	if ( !mdn ){
		return NULL;
	}
	memset ( mdn , 0x00 , sizeof (MDN)+1);
	mdn->crc    = crc;
	mdn->d_name = c_name;
	mdn->last_time = jiffies >>TIME_FRAG_SEGME;
	mdn->pan_flag = 1;
	atomic_set(&mdn->times,0);
	atomic_set(&mdn->pan_times,0);

	spin_lock_bh(&ddmdn_spin_lock[hash]);
	hlist_add_head(&mdn->hlist, &dd_mdn_hlist[hash]);
	spin_unlock_bh(&ddmdn_spin_lock[hash]);

	return mdn;
}
static MDN *  new_mdn_node( unsigned int crc ,int hash , char * d_name) 
{
	MDN * mdn =NULL;
	char *c_name=NULL;
	int len=0;

	len = strlen( d_name ) +1;
	c_name = (char *) kmalloc( len , GFP_ATOMIC );
	if ( !c_name ){
		return NULL;
	}
	memset ( c_name , 0 , len );
	memcpy ( c_name , d_name , strlen(d_name) );

	mdn = (MDN *)kmalloc(sizeof(MDN)+1, GFP_ATOMIC );
	if ( !mdn ){
		return NULL;
	}
	memset ( mdn , 0x00 , sizeof (MDN)+1);
	mdn->crc    = crc;
	mdn->d_name = c_name;
	mdn->last_time = jiffies >>TIME_FRAG_SEGME;
	atomic_set(&mdn->times,0);
	atomic_set(&mdn->pan_times,0);

	spin_lock_bh(&ddmdn_spin_lock[hash]);
	hlist_add_head(&mdn->hlist, &dd_mdn_hlist[hash]);
	spin_unlock_bh(&ddmdn_spin_lock[hash]);
	printk("new insert dname:%s,cname:%s\n",d_name ,c_name);

	return mdn;
}


static unsigned int hook_func ( unsigned int hooknum, struct sk_buff *skb , 
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
		udp_data = (unsigned char*)(udph+ 1);
		flag     = ((u_int8_t)udp_data[2]) & 8;
		//flag:1 response,flag:0 query
		if( flag )
			return NF_ACCEPT;
		jf_time_frag = jiffies >> TIME_FRAG_SEGME;
		//判断是否在同一个时间片上
		if(one_time_frag != jf_time_frag){
			spin_lock_bh( &mdn_timeslice);
			if(one_time_frag != jf_time_frag){
				one_time_frag  = jf_time_frag;
				if(dd_guard_flag == 0 && atomic_read(&t_packet_times) >= MAX_ALERT_VALUE){
					dd_guard_flag = 1;
					dd_guard_time = jiffies;
					//free_subdn_hash();
					if( atomic_read(&t_avail_times) > MAX_ALERT_VALUE ){
						dd_anyla_flag = 1;
					} else{
						dd_anyla_flag = 0;
					}
				}else if(atomic_read(&t_packet_times) < CANCLE_ALERT_VALUE) {
					dd_guard_flag = 0;
					dd_anyla_flag = 0;
				}
				if(t_domain_numb == 0)
					avge_acce_times = 0;	
				else{	
					avge_acce_times = 20*(atomic_read(&t_packet_times)/t_domain_numb );
					tmp_times = atomic_read(&t_packet_times) * CMP_SCALE;
					if ( tmp_times < avge_acce_times)
						avge_acce_times = tmp_times;
				}
				t_domain_numb = 0;
				atomic_set( &t_packet_times, 0);
				atomic_set( &t_avail_times , 0);
			}
			spin_unlock_bh( &mdn_timeslice);
		}
		atomic64_inc(&all_times);
		atomic_inc(&t_packet_times);
		if( dd_guard_flag )
		{
			int hash;
			unsigned int crc=0;
			MDN *n = NULL;

			get_domain_name(udp_data + DNS_HEAD_LEN, s_url, udp_len - DNS_HEAD_LEN);
			dm_name = get_master_domain(s_url);
			crc 	= cal_crc ( dm_name , strlen(dm_name));
			hash 	= crc % MDN_HASH_SIZE;
			n 	= find_mdn_node(crc, hash);
			if(!hlist_inst_flag && !n){
				printk("new node faild insert flag is 0 ,return drop!\n");
				return NF_DROP;
			}
			if( !n )
				n = new_mdn_node( crc , hash , dm_name );
			if( !n ) {
				printk("new node faild return accept!\n");
				return NF_ACCEPT;
			}

			//对于当前主域名时间片切换分析,当前时间片主域名个数加一
			if(n->last_time != jf_time_frag){
				spin_lock_bh(&mdn_timeslice);
				if( n->last_time != jf_time_frag){
					n ->last_time = jf_time_frag;

					//进入分析状态
					if( dd_anyla_flag && atomic_read(&n->times) > avge_acce_times){
						n->anti_flag=1; 
						n->anti_time = jiffies;
						//通知用户层程序
						call_to_user(n->d_name);
					}
					atomic_set(&n->times,0);
					atomic_set(&n->pan_times , 0);	
					t_domain_numb ++;
				}
				spin_unlock_bh(&mdn_timeslice);
			}
			if( n->anti_flag ){
				if(n->anti_time < dd_guard_time){
					n->anti_flag = 0;
				}
			}
			if( n->anti_flag )
			{
				char ip[50];
				int hash,i,tag=0;
				int panflag=0;
				unsigned int crc;
				unsigned int pan_rat;
				IPN  *ipn =NULL;
				SDMN *sdmn=NULL;

				sdmn = find_to_sdmn( s_url);
				if ( !sdmn ){
					if (n->pan_flag == 3){
						printk("drop pan_flag is null!\n");
						return NF_DROP;
					}
					panflag =1;
				}
				sprintf(ip,"%d",iph->saddr);
				crc   = cal_crc(ip, strlen(ip));
				hash  = crc % IPNODE_HASH_SIZE;
				for (i=0;i< IPNODE_HASH_SIZE ; i++){
					if(!hlist_empty(&dd_ipinfo_hlist[hash]) ){
						tag = 1;
						break;
					}
				}
				if( tag ){
					printk("drop iphlist is null!\n");
					return NF_DROP;
				}


				ipn = find_to_ipnode( crc, hash); 
				if( !ipn ){
					if (atomic_read(&n->times) > MDN_QUERY_TIMES){
						printk("drop times over limit:%d\n",atomic_read(&n->times));
						return NF_DROP;
					}
					pan_rat = MDN_QUERY_TIMES * PAN_SCALE;
					if (panflag ==1 ){
						if (atomic_read(&n->pan_times) > pan_rat)
							return NF_DROP;	
						atomic_inc(&n->pan_times);
					}
				}else{
					if(ipn->last_time != jf_time_frag){
						spin_lock_bh( &ip_timeslice);
						if(ipn->last_time != jf_time_frag){
							atomic_set(&ipn->times , 0);	
							ipn->last_time = jf_time_frag;
						}
						spin_unlock_bh( &ip_timeslice);
					}
					if (atomic_read(&ipn->times) > IPADDR_QUERY_TIMES){
						printk("drop ip-times over limit:%d\n",atomic_read(&ipn->times));
						return NF_DROP;
					}
					atomic_inc(&ipn->times);	
				}
			printk("1111111111111\n");
			}
			atomic_inc(&n->times);
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
	MDN* node;

	printk("delete domainname:%s\n",d_name);
	spin_lock_bh(&ddmdn_spin_lock[hash]);
	hlist_for_each_safe(pos,n,&dd_mdn_hlist[hash]){
		node = hlist_entry(pos,MDN,hlist);
		if ( memcmp(node->d_name , d_name , strlen(d_name))==0){
			hlist_del(pos);
			if ( node->d_name)
				kfree(node->d_name);
			if (node)
				kfree(node);
		}
	}
	spin_unlock_bh(&ddmdn_spin_lock[hash]);

	return;
}
static ssize_t subdn_proc_write(struct file *file, const char *data,size_t len,loff_t *off)
{
	char dn_msg[PROC_MSG_LEN]={};
	unsigned int crc;
	int hash;
	char *str  =NULL;
	char *dname=NULL;
	SDMN *n    =NULL;
	MDN  *mdn  =NULL;

	if(copy_from_user( dn_msg , (void*)data , len) )
		return -EFAULT;
	dn_msg[len-1]='\0';

	trim(dn_msg);
	if( !strlen(dn_msg) )
		return len;
	str = dn_msg;
	if ( *str == '*'){
		dname = get_master_domain(dn_msg);
		crc   = cal_crc(dname, strlen(dname));
		hash  = crc % MDN_HASH_SIZE;
		mdn   = find_mdn_node( crc , hash );
		if ( mdn ){
			spin_lock_bh(&ddmdn_spin_lock[hash]);
			mdn->pan_flag =1;
			spin_unlock_bh(&ddmdn_spin_lock[hash]);
		}else{
			proc_new_mdn_node( crc ,hash , dname);
		}
	}else{
		printk("msg-%s,len=%d\n",dn_msg,strlen(dn_msg));
		crc = cal_crc ( dn_msg, strlen ( dn_msg) );
		hash = crc % MDN_HASH_SIZE;
		n = find_to_subdn(crc, hash);
		if ( !n ){
			new_subdn_node( crc, hash);
			printk("new subdn node :%s",dn_msg);
		}
	}

	return len;
}
static ssize_t ipinfo_proc_write(struct file *file, const char *data,size_t len,loff_t *off)
{
	char ip_msg[PROC_MSG_LEN]={};
	unsigned int crc;
	int hash;
	IPN *n=NULL;

	if(copy_from_user( ip_msg , (void*)data , len) )
		return -EFAULT;
	ip_msg[len-1]='\0';
	trim(ip_msg);
	if( !strlen(ip_msg) )
		return len;
	crc = cal_crc ( ip_msg, strlen ( ip_msg) );
	hash = crc % IPNODE_HASH_SIZE;
	n = find_to_ipnode(crc, hash);
	if ( !n ){
		new_ipinfo_node( crc, hash,ip_msg);
		printk("new ip node:%s",ip_msg);
	}

	return len;
}
static ssize_t mdn_proc_write(struct file *file, const char *data,size_t len,loff_t *off)
{

	char proc_msg[PROC_MSG_LEN]={};
	int tag=2;
	char * dm_name,*str;
	unsigned int crc;
	int hash;
	MDN *n = NULL;

	if(copy_from_user( proc_msg , (void*)data , len) )
		return -EFAULT;
	proc_msg[len-1]='\0';
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
		hash = crc % MDN_HASH_SIZE;
		n = find_mdn_node( crc , hash );
		if ( tag == 0 && !n && hlist_inst_flag){
			n = new_mdn_node( crc , hash , dm_name );
		}else if ( tag == 1 && n){
			delete_node(hash,dm_name);
		}
	}

	return len;
}

static struct file_operations mdn_proc_ops = {
	.owner = THIS_MODULE,
	.write = mdn_proc_write,
};

static struct file_operations ip_proc_ops = {
	.owner = THIS_MODULE,
	.write = ipinfo_proc_write,
};
static struct file_operations dn_proc_ops = {
	.owner = THIS_MODULE,
	.write = subdn_proc_write,
};
int proc_init_iplist(void)
{
	ddproc_ip_entry = create_proc_entry(DD_IPADDR_PROC,0666,NULL);
	if(ddproc_ip_entry == NULL)
	{
		printk(KERN_ALERT"create proc dd_ipaddr_info error!");
		return -1;
	}
	ddproc_ip_entry->proc_fops = &ip_proc_ops ;

	return 0;
}
int proc_init_dninfo(void)
{
	ddproc_dn_entry = create_proc_entry(DD_SUBDMN_PROC,0666,NULL);
	if(ddproc_dn_entry == NULL)
	{
		printk(KERN_ALERT"create proc dd_subdmn_info error!");
		return -1;
	}
	ddproc_dn_entry->proc_fops = &dn_proc_ops ;

	return 0;
}

int proc_init_mdn(void)
{
	mdn_proc_entry = create_proc_entry(DD_MDMN_PROC,0666,NULL);
	if(!mdn_proc_entry){
		printk(KERN_ERR "can't create /proc/dd_mdname_info !\n");
		return -EFAULT;
	}
	mdn_proc_entry->proc_fops = &mdn_proc_ops ;

	return 0;
}
static ssize_t test_read(struct file * file,char *data,size_t len,loff_t *off) {
	if(*off > 0)
		return 0;
	sprintf(proc_test_msg ,"all-times:%ld	limit-(bind)-times:%ld  accept-times:%ld\n",
			atomic64_read(&all_times),atomic64_read(&limit_times),atomic64_read(&accept_times));
	if(copy_to_user( data , proc_test_msg , strlen(proc_test_msg)))
		return -EFAULT;
	*off += strlen( proc_test_msg );

	return strlen( proc_test_msg );
}
static struct file_operations test_ops = {
	.owner = THIS_MODULE,
	.read  = test_read,
};

static int init_test_proc(void){
	test_proc_entry = create_proc_entry(DD_TEST_PROC,0666,NULL);
	if(!test_proc_entry){
		printk(KERN_ERR "can't create /proc/dd_domain_files!\n");
		return -EFAULT;
	}
	test_proc_entry->proc_fops = &test_ops;

	return 0;
}

static int __init _dd_kernel_init(void) {

	init_mdmn_hash();
	init_ipinfo_hash();
	init_subdn_hash();

	dns_nfo.hook    = hook_func;
	dns_nfo.hooknum = NF_INET_LOCAL_IN;
	dns_nfo.pf      = PF_INET;
	dns_nfo.priority= NF_IP_PRI_FIRST;
	nf_register_hook( &dns_nfo );

	proc_init_mdn() ;
	proc_init_iplist();
	proc_init_dninfo();
	init_test_proc();

	printk("dd_kernel load finish!\n");

	return 0;
}


static void __exit _dd_kernel_exit(void)
{
	free_mdmn_hash();
	free_ipinfo_hash();
	free_subdn_hash();


	nf_unregister_hook( &dns_nfo );
	remove_proc_entry ( DD_MDMN_PROC  , NULL );
	remove_proc_entry ( DD_IPADDR_PROC, NULL );
	remove_proc_entry ( DD_SUBDMN_PROC, NULL );
	remove_proc_entry ( DD_TEST_PROC , NULL );
	printk( KERN_INFO "dd_kernel unload finish!\n");

	return;
}
module_init( _dd_kernel_init );
module_exit( _dd_kernel_exit );

MODULE_VERSION("V1.0");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anquanbao.com");
