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

MODULE_AUTHOR("Abhishek & Nalin");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("pinet: A Minimal Virtual Network + Char Driver");

#define pinet_RX_INTR 0x0001
#define pinet_TX_INTR 0x0002

#define DEVICE_NAME "pinet"
static int pinet_major;
static struct class *pinet_class;

struct pinet_packet {
    struct pinet_packet *next;
    struct net_device *dev;
    int datalen;
    u8 data[ETH_DATA_LEN];
};

struct pinet_priv {
    struct net_device_stats stats;
    int status;
    struct pinet_packet *rx_queue;
    int rx_int_enabled;
    int tx_packetlen;
    u8 *tx_packetdata;
    struct sk_buff *skb;
    spinlock_t lock;
    struct net_device *dev;
    struct napi_struct napi;
};

static struct net_device *pinet_dev;

static void pinet_release_buffer(struct pinet_packet *pkt)
{
    kfree(pkt);
}

void pinet_rx(struct net_device *dev, struct pinet_packet *pkt)
{
    printk(KERN_INFO "pinet_rx payload: %.*s\n", pkt->datalen, pkt->data);
    struct sk_buff *skb;
    struct pinet_priv *priv = netdev_priv(dev);

    skb = dev_alloc_skb(pkt->datalen + 2);
    if (!skb) {
        printk(KERN_NOTICE "pinet rx: low on mem - packet dropped\n");
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

static netdev_tx_t pinet_tx(struct sk_buff *skb, struct net_device *dev)
{
    printk(KERN_INFO "pinet_tx payload: %.*s\n", skb->len, skb->data);
    struct pinet_priv *priv = netdev_priv(dev);
    struct pinet_packet *pkt;

    if (skb->len > ETH_DATA_LEN) {
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }

    pkt = kmalloc(sizeof(struct pinet_packet), GFP_ATOMIC);
    if (!pkt) {
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }

    memcpy(pkt->data, skb->data, skb->len);
    pkt->datalen = skb->len;
    pkt->dev = dev;

    spin_lock(&priv->lock);
    pkt->next = priv->rx_queue;
    priv->rx_queue = pkt;
    priv->status |= pinet_RX_INTR;
    spin_unlock(&priv->lock);

    dev_kfree_skb(skb);
    pinet_regular_interrupt(0, dev, NULL);
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
    dev->tx_queue_len = 1000;
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

    printk(KERN_INFO "pinet: Received from user: %s\n", kbuf);

    struct pinet_packet *pkt = kmalloc(sizeof(struct pinet_packet), GFP_KERNEL);
    if (!pkt)
        return -ENOMEM;

    memcpy(pkt->data, kbuf, len);
    pkt->datalen = len;
    pkt->dev = pinet_dev;

    pinet_rx(pinet_dev, pkt);
    return len;
}

static const struct file_operations pinet_fops = {
    .owner = THIS_MODULE,
    .write = pinet_char_write,
};

static int __init pinet_init(void)
{
    int ret;
    pr_info("pinet: Initializing\n");
    pinet_dev = alloc_netdev(sizeof(struct pinet_priv), "pinet%d", NET_NAME_UNKNOWN, pinet_setup);
    if (!pinet_dev)
        return -ENOMEM;

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
        unregister_netdev(pinet_dev);
        free_netdev(pinet_dev);
    }
}

module_init(pinet_init);
module_exit(pinet_exit);
