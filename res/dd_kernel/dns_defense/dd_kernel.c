#ifndef __KERNEL__
#define __KERNEL__
#endif

#ifndef MODULE
#define MODULE
#endif

#include<linux/init.h>
#include<linux/kernel.h>
#include<linux/module.h>

#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<linux/icmp.h>
#include<linux/spinlock.h>


#define DNS_HEAD_LEN 12
#define STR_IP(str, n) sprintf((str), "%u.%u.%u.%u", (n)  & 0xff, ((n)>> 8) & 0xff, ((n)>>16) & 0xff, ((n)>>24) & 0xff)
#define DNS_PORT 53
#define UDP_HEAD_LEN 8
#define DOMAIN_HASH_SIZE  1000
#define REQ_THOLD_NUMB 10000
#define CRC_MUL 0x1021    /*生成多项式*/
#define TPDL_LEN 21
#define DD_PROC_NAME "dd_domain_files"
#define MAX_HOLD_TIMES  20




static char proc_msg[512]={"Anquanbao.com\n"};
static struct hlist_head _dd_domain_hlist[DOMAIN_HASH_SIZE];
spinlock_t _dlist_spin_lock[DOMAIN_HASH_SIZE];
spinlock_t _time_frag_lock = SPIN_LOCK_UNLOCKED;
spinlock_t _rdn_inc_lock = SPIN_LOCK_UNLOCKED;

static unsigned long _total_time_frag = 0;



static unsigned long _t_req_p_len   =0;
static unsigned long _tmp_req_p_len =0;
static unsigned long _a_req_times   =1;
static unsigned long _t_req_d_len   =0;


typedef struct _dns_domain_node {
	unsigned int  crc;
	unsigned int  r_num;
	unsigned long t_frag;
	u8 flag; 
	char * d_name;
	struct hlist_node hlist;
}_DDH_;

static unsigned _dd_guard_flag = 0;
static struct nf_hook_ops _dnsnfo;

#if 0
static unsigned int _get_domain_name(const char* addr, char* urlbuff, int len);
static void _init_hash_size ( void );
static void _free_hash_size(void) ;
static int  _create_dns_info( unsigned int crc , int  hash , char * d_name)
static unsigned int _cal_crc(unsigned char *ptr,unsigned char len) ;
static int _domain_info_add( char * d_name);

#endif


static char *_get_master_domain(char *domain)
{
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


static unsigned int _get_domain_name(const char* addr, char* urlbuff, int len)
{
    const char * p = addr;
    int pos = 0;


    while(p && (*p > 0)) {
        if(*p > len) {
            printk("error url len: %d\n", *p);
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

static void _init_hash_size ( void )
{
	unsigned int i;
	for( i = 0 ; i< DOMAIN_HASH_SIZE ; i++)
	{
		INIT_HLIST_HEAD( &_dd_domain_hlist[i] );
		spin_lock_init ( &_dlist_spin_lock[i] );
	}
	spin_lock_init( &_time_frag_lock );
	//spin_lock_init( &_rdn_inc_lock   );
	return;
}

static void _free_hash_size(void) {
		unsigned int i = 0;
		struct hlist_node *pos,*n;
		_DDH_* node;
		for( i = 0 ; i < DOMAIN_HASH_SIZE ; i++ ) {
			spin_lock_bh(&_dlist_spin_lock[i]);
			hlist_for_each_safe(pos,n,&_dd_domain_hlist[i]){
				node = hlist_entry(pos,_DDH_,hlist);
				hlist_del(pos);
				printk("free domain:%s;r_num:%d;crc:%d]\n" , node->d_name , node->r_num , node->crc);
				if ( node->d_name)
					kfree(node->d_name);
				if (node)
					kfree(node);
			}
			spin_unlock_bh(&_dlist_spin_lock[i]);
		}
		return ;
}
static int  _create_dns_info( unsigned int crc , int  hash , char * d_name)
{

	char *d_url = (char *) kmalloc( strlen( d_name )+ 1 , GFP_ATOMIC );
	if (d_url == NULL){
		return NF_ACCEPT;
	}
	memcpy ( d_url , d_name , strlen(d_name) );
	d_url[strlen(d_name)]='\0';

	printk( "query url:[%s],hash:[%d]\n",d_url ,hash);

	_DDH_ * _ddn = (struct _dns_domain_node *)kmalloc(sizeof(struct _dns_domain_node), GFP_ATOMIC );
	if ( _ddn == NULL ){
		return -1;
	}
	_ddn->crc    = crc;
	_ddn->r_num  =  1;
	_ddn->flag   = '0';
	_ddn->d_name = d_url;
	_t_req_d_len += 1;
	_ddn->t_frag = jiffies >> 10;

	hlist_add_head(&_ddn->hlist, &_dd_domain_hlist[hash]);

	return 0;
}
static  unsigned int _cal_crc(unsigned char *ptr , unsigned char len) {
	unsigned char i;
	unsigned int crc=0;
	while(len--!=0) {
		for(i=0x80; i!=0; i/=2) {
			if((crc&0x8000)!=0) {crc*=2; crc^=CRC_MUL;}   /* 余式CRC乘以2再求CRC  */
			else crc*=2;
			if((*ptr&i)!=0) crc^=CRC_MUL;                /* 再加上本位的CRC */
		}
		ptr++;
	}
	return(crc);
}

static int _domain_info_add( char * d_name)
{
	unsigned int _crc;
	struct hlist_node *_pos;
	struct _dns_domain_node *_ddn = NULL;
	int tag = 0;
	int hash;


	_crc = _cal_crc ( d_name , strlen ( d_name ) );
	hash = _crc % DOMAIN_HASH_SIZE;
	spin_lock_bh( &_dlist_spin_lock[hash] );
	hlist_for_each_entry ( _ddn , _pos , &_dd_domain_hlist[hash] , hlist ){
		//if( (_ddn->crc == _crc) && ( memcmp( _ddn->d_name , d_name , strlen( _ddn->d_name)) == 0) ){
		if( (_ddn->crc == _crc) ){
			if( _ddn-> t_frag != jiffies >> 10 ){
				_ddn->t_frag =jiffies >> 10;
				_ddn->r_num = 0;
				
			}
			tag = 1;
			_ddn->r_num  += 1;
			break;

		}
	}
	if(!tag &&  _create_dns_info( _crc, hash, d_name ) == 0){
		spin_unlock_bh( &_dlist_spin_lock[hash] );
		return(-1);
	}

	spin_unlock_bh( &_dlist_spin_lock[hash] );
	
	return 0;
}

#if 0
static void _print_dns_info(const unsigned char *buf, int len ,char* host)
{
        char ss[4];
        int index;
        int HOST_S = REQ_HOST_NAME_OFFSET;

        memset(host, 0, 256);

        while (HOST_S < len && buf[HOST_S] >0)
        {
                if (strlen(host) >0 )
                {
                        strcat(host, ".");
                }
                index = 1;
                while (HOST_S + index < len && index <= buf[HOST_S])
                {
                        memset(ss, 0, 4);
                        sprintf(ss, "%c", buf[HOST_S + index]);
                        strcat(host, ss);
                        index++;
                }
                HOST_S += (buf[HOST_S] + 1);
        }
        printk("<0>DNS Packet's Host:%s, Data Length:%d\n", host, len);
}

#endif 
static unsigned int _hook_func ( unsigned int hooknum, struct sk_buff *skb , 
	const struct net_device *in, const struct net_device *out, 
	int (*okfn)(struct sk_buff *) )
{
	struct sk_buff* sb =skb;
	struct udphdr * udph;
	struct iphdr  * iph  = ip_hdr(sb);
#if 1
	unsigned char src_ip[4],dst_ip[4];
#endif
	char s_url[1024] = {0};

	char * udp_data;
	char * dd_str;
      	u_int16_t src_port, dst_port;
    	u_int16_t udp_len = 0;
    	u_int8_t flag;
 	char src[20] = {0},dst[20]={0};
	

	/*取出IP地址*/
	*(unsigned int*)src_ip=iph->saddr;
	*(unsigned int*)dst_ip=iph->daddr;
	if ( iph->protocol == IPPROTO_UDP){
#if 1
		udph     = (struct udphdr*)(sb->data+(iph->ihl*4));
		src_port = ntohs(udph->source);
		dst_port = ntohs(udph->dest);
		udp_len  = ntohs(udph->len) - UDP_HEAD_LEN;
		if(udp_len <= DNS_HEAD_LEN) {
			return NF_DROP;
		}
		/* get to start point of udp data	*/
		udp_data = (unsigned char*)(udph+ 1);
		flag     = ((u_int8_t)udp_data[2]) & 8;
		if( ( dst_port != DNS_PORT ) || flag  )
			return NF_ACCEPT;

		_dd_guard_flag = 0;

#if 1
		//判断是否在同一个时间片上
		if( _total_time_frag != jiffies >> 10 ){
			spin_lock_bh( &_time_frag_lock );
			if( _total_time_frag != jiffies >> 10 ){
				_total_time_frag  = jiffies >>10 ;
				if ( (_t_req_p_len >= _t_req_d_len) && (_t_req_d_len > 0) ){
					_a_req_times = _t_req_p_len / _t_req_d_len;
				}
				printk(" onece time frag packet total number=%d\n" , _t_req_p_len);
			}
			spin_unlock_bh( &_time_frag_lock );
		}
#endif
		_get_domain_name ( udp_data + DNS_HEAD_LEN, s_url, udp_len - DNS_HEAD_LEN );
		dd_str = _get_master_domain(s_url);
		printk("_get_domain_name:[%s]main :[%s] \n", s_url ,dd_str);
		printk("ip:%s, port:%u, dip:%s, dport:%u, len:%u, type:%s\n", 	
			 	src, src_port, dst, dst_port, udp_len, flag ? "response" : "query"); 
#endif
#if 0
		if (    _t_req_p_len    > THOLD_PACKET_NUMB ){
			printk (" dns request over max \n");
			_dd_guard_flag = 1;
			return NF_DROP;
		}
#endif

#if 0
		printk("Packetfrom:%d.%d.%d.%d,to:%d.%d.%d.%d \n",  
				src_ip[0],src_ip[1],src_ip[2],src_ip[3],
				dst_ip[0],dst_ip[1],dst_ip[2],dst_ip[3]);
		spin_lock_bh( &_time_frag_lock);
		_t_req_p_len++;
		spin_unlock_bh( &_time_frag_lock);
#endif

		_domain_info_add( dd_str );

		if ( _tmp_req_p_len > REQ_THOLD_NUMB ){
			
		}

			

		if ( _dd_guard_flag ){
			//进入防御
			//
			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}





static struct proc_dir_entry * ddproc_entry = NULL;
static int dd_proc_read(struct file * file,char *data,size_t len,loff_t *off)
{
    if(*off > 0)
	    return 0;
    if(copy_to_user( data , proc_msg , strlen(proc_msg)))
	    return -EFAULT;
    *off += strlen( proc_msg );
printk(KERN_ERR "READ.....:content:%s\n",proc_msg);
    return strlen( proc_msg );
}

static int dd_proc_write(struct file *file, const char *data,size_t len,loff_t *off)
{
printk(KERN_ERR "write.............\n");

    if(copy_from_user( proc_msg , (void*)data , len) )
	    return -EFAULT;
    proc_msg[len]='0';
printk(KERN_ERR "MSG=%s\n" , proc_msg );
    return len;
}

static struct file_operations dd_proc_ops = {
   .owner = THIS_MODULE,
   .read  = dd_proc_read,
   .write = dd_proc_write,
};


static int __init _dd_kernel_init(void)
{
	_init_hash_size();
	_dnsnfo.hook    = _hook_func;
	_dnsnfo.hooknum = NF_INET_LOCAL_IN;
	_dnsnfo.pf      = PF_INET;
	_dnsnfo.priority= NF_IP_PRI_FIRST;
	nf_register_hook( &_dnsnfo );

    	ddproc_entry = create_proc_entry(DD_PROC_NAME,0666,NULL);
    	if(!ddproc_entry){
	    printk(KERN_ERR "can't create /proc/dd_domain_files!\n");
	    return -EFAULT;
    	}
    	ddproc_entry->proc_fops = &dd_proc_ops ;


	printk("_init dd_kernel init!\n");
	return 0;
}


static void __exit _dd_kernel_exit(void)
{
	printk(" _t_req_d_len= %ld\n",_t_req_d_len);
	_free_hash_size ();
	nf_unregister_hook( &_dnsnfo );
	remove_proc_entry ( DD_PROC_NAME , NULL );
	printk( KERN_INFO "_exit dd_kernel module!\n");
	return;
}
module_init( _dd_kernel_init );
module_exit( _dd_kernel_exit );

MODULE_VERSION("V1.0");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anquanbao.com");
