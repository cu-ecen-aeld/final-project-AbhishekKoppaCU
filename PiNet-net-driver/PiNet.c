/*
 * pinet.c - A Minimal Linux Network + Character Driver (Virtual)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/ip.h>       
#include <linux/udp.h>
#include <linux/inet.h>     

MODULE_AUTHOR("Abhishek & Nalin");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("pinet: A Minimal Virtual Network + Char Driver");

#define pinet_RX_INTR 0x0001
#define pinet_TX_INTR 0x0002

#define PINET_MAX_PAYLOAD 4  // Limit payload to 4 bytes (int-sized)
#define PINET_QUEUE_DEPTH  1024

#define DEVICE_NAME "pinet"
#define DEVICE "/dev/pinet"


#define PINET_SENSOR_SRC_IP   "192.168.1.10" // dummy local IP
#define PINET_SENSOR_DST_IP   "192.168.1.99" // your pinet app IP
#define PINET_SENSOR_SRC_PORT 1234
#define PINET_SENSOR_DST_PORT 5678

#define PINET_IOCTL_SEND_SENSOR_DATA _IOW('p', 1, int)


static int pinet_major;
static struct class *pinet_class;

struct pinet_packet {
    struct pinet_packet *next;
    struct net_device *dev;

    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    int datalen;
    u8 data[PINET_MAX_PAYLOAD];
};


struct pinet_priv {
    struct net_device_stats stats;

    int status;                     // Interrupt status / driver state
    struct pinet_packet *rx_queue; // Incoming packets from socket netif_rx()
    struct pinet_packet *tx_queue; // Outgoing packets to be read via /dev/pinet
    //int tx_queue_len;

    int rx_int_enabled;

    int tx_packetlen;              // Current TX buffer length
    u8 *tx_packetdata;             // Pointer to TX buffer

    struct sk_buff *skb;

    spinlock_t lock;               // Lock for accessing tx/rx queues
    struct net_device *dev;

    struct napi_struct napi;       // NAPI support (if enabled)
};




static struct net_device *pinet_dev;

static void pinet_release_buffer(struct pinet_packet *pkt)
{
    kfree(pkt);
}


void pinet_rx(struct net_device *dev, struct pinet_packet *pkt)
{
    printk(KERN_NOTICE "pinet_rx received a packet with payload: %.*s\n", pkt->datalen, pkt->data);

    // First, extract the sensor value and write to /tmp/proxpipe
    if (pkt->datalen >= sizeof(int)) {
        int sensor_value;
        memcpy(&sensor_value, pkt->data, sizeof(sensor_value));

        printk(KERN_NOTICE "pinet_rx: Extracted sensor value = %d\n", sensor_value);

        struct file *pipe_filp;
        loff_t pos = 0;

        pipe_filp = filp_open("/tmp/proxpipe", O_WRONLY | O_NONBLOCK, 0);
        if (!IS_ERR(pipe_filp)) {
            kernel_write(pipe_filp, (char *)&sensor_value, sizeof(sensor_value), &pos);
            //filp_close(pipe_filp, NULL);
        } else {
            printk(KERN_NOTICE "pinet_rx: Failed to open /tmp/proxpipe for writing\n");
        }
    } else {
        printk(KERN_NOTICE "pinet_rx: Packet too small, skipping /tmp/proxpipe write\n");
    }

    struct sk_buff *skb;
    struct pinet_priv *priv = netdev_priv(dev);

    skb = dev_alloc_skb(pkt->datalen + 2);
    if (!skb) {
        printk(KERN_NOTICE "pinet_rx: low on mem - packet dropped\n");
        priv->stats.rx_dropped++;
        goto out;
    }

    skb_reserve(skb, 2);
    memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);
    skb->dev = dev;
    skb->protocol = eth_type_trans(skb, dev);
    skb->ip_summed = CHECKSUM_UNNECESSARY;

    priv->stats.rx_packets++;
    priv->stats.rx_bytes += pkt->datalen;

    netif_rx(skb);

out:
    return;
}


static void pinet_regular_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    int statusword;
    struct pinet_priv *priv;
    struct pinet_packet *pkt = NULL;
    struct net_device *dev = (struct net_device *)dev_id;

    if (!dev)
        return;

    priv = netdev_priv(dev);
    spin_lock(&priv->lock);
    statusword = priv->status;
    priv->status = 0;

    if (statusword & pinet_RX_INTR) {
        pkt = priv->rx_queue;
        if (pkt) {
            priv->rx_queue = pkt->next;
            pinet_rx(dev, pkt);
        }
    }

    if (statusword & pinet_TX_INTR) {
        priv->stats.tx_packets++;
        priv->stats.tx_bytes += priv->tx_packetlen;
        dev_kfree_skb(priv->skb);
    }

    spin_unlock(&priv->lock);
    if (pkt)
        pinet_release_buffer(pkt);
}
 

struct packet_info {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t payload_len;
    char payload[PINET_MAX_PAYLOAD];
};

static netdev_tx_t pinet_tx(struct sk_buff *skb, struct net_device *dev)
{
    struct pinet_priv *priv = netdev_priv(dev);

    if (!skb) {
        printk(KERN_NOTICE "pinet_tx: skb is NULL\n");
        return NETDEV_TX_OK;
    }

    if (skb->protocol != htons(ETH_P_IP)) {
        printk(KERN_NOTICE "pinet_tx: Not an IP packet, protocol=0x%x\n", ntohs(skb->protocol));
        return NETDEV_TX_OK;
    }

    if (!pskb_may_pull(skb, sizeof(struct iphdr) + sizeof(struct udphdr) + PINET_MAX_PAYLOAD)) {
        printk(KERN_NOTICE "pinet_tx: Packet too short, cannot pull headers\n");
        return NETDEV_TX_OK;
    }

    struct iphdr *iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_UDP) {
        printk(KERN_NOTICE "pinet_tx: Not a UDP packet, protocol=%d\n", iph->protocol);
        return NETDEV_TX_OK;
    }

    struct udphdr *udph = udp_hdr(skb);
    int udp_payload_len = ntohs(udph->len) - sizeof(struct udphdr);
    if (udp_payload_len != PINET_MAX_PAYLOAD) {
        printk(KERN_NOTICE "pinet_tx: UDP payload length mismatch: %d (expected %d)\n",
               udp_payload_len, PINET_MAX_PAYLOAD);
        return NETDEV_TX_OK;
    }

    struct pinet_packet *pkt = kzalloc(sizeof(struct pinet_packet), GFP_ATOMIC);
    if (!pkt) {
        printk(KERN_NOTICE "pinet_tx: Failed to allocate pinet_packet\n");
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }

    unsigned char *udp_payload = (unsigned char *)(udp_hdr(skb) + 1);
    memcpy(pkt->data, udp_payload, PINET_MAX_PAYLOAD);
    printk(KERN_DEBUG "pinet_tx: extracted payload = %d\n", *(int *)pkt->data);

    pkt->datalen = PINET_MAX_PAYLOAD;
    pkt->dev = dev;
    pkt->src_ip = iph->saddr;
    pkt->dst_ip = iph->daddr;
    pkt->src_port = ntohs(udph->source);
    pkt->dst_port = ntohs(udph->dest);

    printk(KERN_DEBUG "pinet_tx: accepted packet from %pI4:%u to %pI4:%u, payload=%d\n",
           &pkt->src_ip, pkt->src_port, &pkt->dst_ip, pkt->dst_port,
           *(int *)pkt->data);

    // Push into tx_queue
    spin_lock(&priv->lock);
    pkt->next = priv->tx_queue;
    priv->tx_queue = pkt;
    spin_unlock(&priv->lock);

    dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}

static int pinet_open(struct net_device *dev)
{
    netif_start_queue(dev);
    return 0;
}

static int pinet_stop(struct net_device *dev)
{
    netif_stop_queue(dev);
    return 0;
}

static struct net_device_stats *pinet_get_stats(struct net_device *dev)
{
    struct pinet_priv *priv = netdev_priv(dev);
    return &priv->stats;
}

static const struct net_device_ops pinet_netdev_ops = {
    .ndo_open = pinet_open,
    .ndo_stop = pinet_stop,
    .ndo_start_xmit = pinet_tx,
    .ndo_get_stats = pinet_get_stats,
};

static void pinet_setup(struct net_device *dev)
{
    ether_setup(dev);
    dev->netdev_ops = &pinet_netdev_ops;
    dev->flags |= IFF_NOARP;
    dev->features |= NETIF_F_HW_CSUM;
    //dev->tx_queue_len = 1000;
    eth_hw_addr_random(dev);

    struct pinet_priv *priv = netdev_priv(dev);
    memset(priv, 0, sizeof(struct pinet_priv));
    spin_lock_init(&priv->lock);
    priv->dev = dev;
}

// === Char Device ===

static ssize_t pinet_char_write(struct file *file, const char __user *buf, size_t len, loff_t *off)
{
    char kbuf[128] = {0};
    if (len > sizeof(kbuf) - 1)
        len = sizeof(kbuf) - 1;

    if (copy_from_user(kbuf, buf, len))
        return -EFAULT;

    printk(KERN_NOTICE "pinet: Received from user: %s\n", kbuf);

    struct pinet_packet *pkt = kmalloc(sizeof(struct pinet_packet), GFP_KERNEL);
    if (!pkt)
        return -ENOMEM;

    memcpy(pkt->data, kbuf, len);
    pkt->datalen = len;
    pkt->dev = pinet_dev;

    pinet_rx(pinet_dev, pkt);
    return len;
}

ssize_t pinet_char_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
    struct net_device *dev = filp->private_data;
    struct pinet_priv *priv = netdev_priv(dev);
    struct pinet_packet *pkt;
    ssize_t ret = 0;

    if (!dev)
        return -EINVAL;

    if (count < PINET_MAX_PAYLOAD)
        return -EINVAL;

    spin_lock(&priv->lock);
    pkt = priv->tx_queue;

    if (!pkt) {
        spin_unlock(&priv->lock);
        return 0; // No data
    }

    // Now copy the data FIRST
    if (copy_to_user(buf, pkt->data, pkt->datalen)) {
        spin_unlock(&priv->lock);
        return -EFAULT;
    }

    // Only after SUCCESSFUL copy: pop the packet
    priv->tx_queue = pkt->next;
    //priv->tx_queue_len--;
    spin_unlock(&priv->lock);

    ret = pkt->datalen;
    kfree(pkt);

    return ret;
}

int pinet_send_sensor_data(uint8_t *data, size_t len)
{
    struct sk_buff *skb;
    struct iphdr *iph;
    struct udphdr *udph;
    uint8_t *payload;
    size_t total_len = sizeof(struct iphdr) + sizeof(struct udphdr) + len;

    if (!pinet_dev || !pinet_dev->netdev_ops) {
        printk(KERN_NOTICE "pinet_send_sensor_data: pinet_dev not ready\n");
        return -ENODEV;
    }

    skb = alloc_skb(total_len + NET_IP_ALIGN, GFP_ATOMIC);
    if (!skb) {
        printk(KERN_NOTICE "pinet_send_sensor_data: Failed to allocate skb\n");
        return -ENOMEM;
    }

    skb_reserve(skb, NET_IP_ALIGN);
    payload = skb_put(skb, total_len);

    // Fill UDP payload
    memcpy(payload + sizeof(struct iphdr) + sizeof(struct udphdr), data, len);

    // Fill UDP header
    udph = (struct udphdr *)(payload + sizeof(struct iphdr));
    udph->source = htons(PINET_SENSOR_SRC_PORT);
    udph->dest   = htons(PINET_SENSOR_DST_PORT);
    udph->len    = htons(sizeof(struct udphdr) + len);
    udph->check  = 0;

    // Fill IP header
    iph = (struct iphdr *)payload;
    iph->version  = 4;
    iph->ihl      = 5;
    iph->tos      = 0;
    iph->tot_len  = htons(total_len);
    iph->id       = 0;
    iph->frag_off = 0;
    iph->ttl      = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr    = in_aton(PINET_SENSOR_SRC_IP);
    iph->daddr    = in_aton(PINET_SENSOR_DST_IP);
    iph->check    = 0;

    skb->dev = pinet_dev;
    skb->protocol = htons(ETH_P_IP);
    skb->ip_summed = CHECKSUM_UNNECESSARY;
    skb_reset_network_header(skb);
    skb_set_transport_header(skb, sizeof(struct iphdr)); 

    printk(KERN_DEBUG "pinet_send_sensor_data: Successfully created skb, sending to pinet_tx\n");
    return pinet_tx(skb, pinet_dev);
}

static long pinet_char_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int sensor_value;

    switch (cmd) {
    case PINET_IOCTL_SEND_SENSOR_DATA:
        if (copy_from_user(&sensor_value, (int __user *)arg, sizeof(sensor_value)))
            return -EFAULT;

        printk(KERN_NOTICE "pinet: ioctl received sensor data = %d\n", sensor_value);

        return pinet_send_sensor_data((uint8_t *)&sensor_value, sizeof(sensor_value));

    default:
        return -EINVAL;
    }
}


static void pinet_flush_tx_queue(struct pinet_priv *priv)
{
    struct pinet_packet *pkt, *next_pkt;

    spin_lock(&priv->lock);

    pkt = priv->tx_queue;
    priv->tx_queue = NULL;
    //priv->tx_queue_len = 0;

    spin_unlock(&priv->lock);

    while (pkt) {
        next_pkt = pkt->next;
        kfree(pkt);
        pkt = next_pkt;
    }

    printk(KERN_NOTICE "pinet: tx_queue flushed\n");
}




static int pinet_char_open(struct inode *inode, struct file *file)
{
    file->private_data = pinet_dev;  // Associate netdev for access
    return 0;
}


static const struct file_operations pinet_fops = {
    .owner = THIS_MODULE,
    .open  = pinet_char_open,     
    .write = pinet_char_write,
    .read  = pinet_char_read,
    .unlocked_ioctl = pinet_char_ioctl,
};


static int __init pinet_init(void)
{
    int ret;
    pr_info("pinet: Initializing\n");
    pinet_dev = alloc_netdev(sizeof(struct pinet_priv), "pinet%d", NET_NAME_UNKNOWN, pinet_setup);
    if (!pinet_dev)
        return -ENOMEM;
        
    pinet_flush_tx_queue(netdev_priv(pinet_dev));

    ret = register_netdev(pinet_dev);
    if (ret)
        return ret;

    pinet_major = register_chrdev(0, DEVICE_NAME, &pinet_fops);
    if (pinet_major < 0) {
        unregister_netdev(pinet_dev);
        return pinet_major;
    }
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
    	pinet_class = class_create("pinet_class");
    #else
        pinet_class = class_create(THIS_MODULE, "pinet_class");
    #endif
    
    if (IS_ERR(pinet_class)) {
        unregister_chrdev(pinet_major, DEVICE_NAME);
        unregister_netdev(pinet_dev);
        return PTR_ERR(pinet_class);
    }

    device_create(pinet_class, NULL, MKDEV(pinet_major, 0), NULL, DEVICE_NAME);
    pr_info("pinet: Char device /dev/%s created, major %d\n", DEVICE_NAME, pinet_major);

    return 0;
}

static void __exit pinet_exit(void)
{
    pr_info("pinet: Exiting\n");
    device_destroy(pinet_class, MKDEV(pinet_major, 0));
    class_destroy(pinet_class);
    unregister_chrdev(pinet_major, DEVICE_NAME);

    if (pinet_dev) {
        pinet_flush_tx_queue(netdev_priv(pinet_dev));
        unregister_netdev(pinet_dev);
        free_netdev(pinet_dev);
    }
}

module_init(pinet_init);
module_exit(pinet_exit);
