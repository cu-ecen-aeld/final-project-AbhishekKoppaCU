/*
 * pinet.c - A Minimal Linux Network Driver (Virtual)
 * Inspired by snull.c from LDD3
 */

 #include <linux/module.h>
 #include <linux/kernel.h>
 #include <linux/init.h>
 #include <linux/netdevice.h>
 #include <linux/etherdevice.h>
 #include <linux/skbuff.h>
 #include <linux/spinlock.h>
 #include <linux/slab.h>
 
 MODULE_AUTHOR("Abhishek & Nalin");
 MODULE_LICENSE("GPL");
 MODULE_DESCRIPTION("pinet: A Minimal Virtual Network Driver");
 
 #define pinet_RX_INTR 0x0001
 #define pinet_TX_INTR 0x0002
 
 struct pinet_packet {
	 struct pinet_packet *next;
	 struct net_device *dev;
	 int datalen;
	 u8 data[ETH_DATA_LEN];
 };
 
 struct pinet_priv {
	 struct net_device_stats stats;
	 int status;
	 struct pinet_packet *rx_queue;  /* List of incoming packets */
	 int rx_int_enabled;
	 int tx_packetlen;
	 u8 *tx_packetdata;
	 struct sk_buff *skb;
	 spinlock_t lock;
	 struct net_device *dev;
	 struct napi_struct napi;
 };
 
 static struct net_device *pinet_dev;
 
 /* ---- Forward declarations ---- */
 static void pinet_release_buffer(struct pinet_packet *pkt);
 void pinet_rx(struct net_device *dev, struct pinet_packet *pkt);
 static void pinet_regular_interrupt(int irq, void *dev_id, struct pt_regs *regs);
 
 /* ---- Transmit Packet ---- */
 static netdev_tx_t pinet_tx(struct sk_buff *skb, struct net_device *dev)
 {
	 printk(KERN_INFO "pinet_tx payload: %.*s\n", skb->len, skb->data);
	 struct pinet_priv *priv = netdev_priv(dev);
	 struct pinet_packet *pkt;
 
	 pr_info("pinet: Transmitting packet, length: %u bytes\n", skb->len);
 
	 if (skb->len > ETH_DATA_LEN) {
		 dev_kfree_skb(skb);
		 return NETDEV_TX_OK;
	 }
 
	 pkt = kmalloc(sizeof(struct pinet_packet), GFP_ATOMIC);
	 if (!pkt) {
		 pr_err("pinet: TX failed, out of memory\n");
		 dev_kfree_skb(skb);
		 return NETDEV_TX_OK;
	 }
 
	 memcpy(pkt->data, skb->data, skb->len);
	 pkt->datalen = skb->len;
	 pkt->dev = dev;

	 

 
	 /* Queue for RX */
	 spin_lock(&priv->lock);
	 pkt->next = priv->rx_queue;
	 priv->rx_queue = pkt;
	 priv->status |= pinet_RX_INTR;
	 spin_unlock(&priv->lock);
 
	 dev_kfree_skb(skb);
 
	 /* Simulate interrupt */
	 pinet_regular_interrupt(0, dev, NULL);
 
	 return NETDEV_TX_OK;
 }
 
 /* ---- Receive Handler ---- */
 void pinet_rx(struct net_device *dev, struct pinet_packet *pkt)
 {
	 printk(KERN_INFO "pinet_rx payload: %.*s\n", pkt->datalen, pkt->data);
	 struct sk_buff *skb;
	 struct pinet_priv *priv = netdev_priv(dev);
 
	 skb = dev_alloc_skb(pkt->datalen + 2);
	 if (!skb) {
		 if (printk_ratelimit())
			 printk(KERN_NOTICE "pinet rx: low on mem - packet dropped\n");
		 priv->stats.rx_dropped++;
		 goto out;
	 }
 
	 skb_reserve(skb, 2); /* Align IP on 16B boundary */
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
 
 /* ---- Free Packet Buffer ---- */
 static void pinet_release_buffer(struct pinet_packet *pkt)
 {
	 kfree(pkt);
 }
 
 /* ---- Simulated Interrupt Handler ---- */
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
 
 /* ---- Open Device ---- */
 static int pinet_open(struct net_device *dev)
 {
	 pr_info("pinet: Device opened\n");
	 netif_start_queue(dev);
	 return 0;
 }
 
 /* ---- Stop Device ---- */
 static int pinet_stop(struct net_device *dev)
 {
	 pr_info("pinet: Device stopped\n");
	 netif_stop_queue(dev);
	 return 0;
 }
 
 /* ---- Get Stats ---- */
 static struct net_device_stats *pinet_get_stats(struct net_device *dev)
 {
	 struct pinet_priv *priv = netdev_priv(dev);
	 return &priv->stats;
 }
 
 /* ---- Net Device Ops ---- */
 static const struct net_device_ops pinet_netdev_ops = {
	 .ndo_open       = pinet_open,
	 .ndo_stop       = pinet_stop,
	 .ndo_start_xmit = pinet_tx,
	 .ndo_get_stats  = pinet_get_stats,
 };
 
 /* ---- Device Setup ---- */
 static void pinet_setup(struct net_device *dev)
 {
	 ether_setup(dev);
	 dev->netdev_ops = &pinet_netdev_ops;
	 dev->flags |= IFF_NOARP;
	 dev->features |= NETIF_F_HW_CSUM;
	 dev->tx_queue_len = 1000;
	 eth_hw_addr_random(dev);  // Assign random MAC address
 
	 struct pinet_priv *priv = netdev_priv(dev);
	 memset(priv, 0, sizeof(struct pinet_priv));
	 spin_lock_init(&priv->lock);
	 priv->dev = dev;
 }
 
 /* ---- Module Init ---- */
 static int __init pinet_init(void)
 {
	 pr_info("pinet: Initializing\n");
	 pinet_dev = alloc_netdev(sizeof(struct pinet_priv), "pinet%d", NET_NAME_UNKNOWN, pinet_setup);
	 if (!pinet_dev)
		 return -ENOMEM;
	 return register_netdev(pinet_dev);
 }
 
 /* ---- Module Exit ---- */
 static void __exit pinet_exit(void)
 {
	 pr_info("pinet: Exiting\n");
	 if (pinet_dev) {
		 unregister_netdev(pinet_dev);
		 free_netdev(pinet_dev);
	 }
 }
 
 module_init(pinet_init);
 module_exit(pinet_exit);
 