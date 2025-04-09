/*
 * PiNet.c - A Minimal Linux Network Driver (Virtual)
 * Inspired by snull.c from LDD3
 */

 #include <linux/module.h>
 #include <linux/kernel.h>
 #include <linux/init.h>
 #include <linux/netdevice.h>
 #include <linux/etherdevice.h>
 
 MODULE_AUTHOR("Abhishek & Nalin");
 MODULE_LICENSE("GPL");
 MODULE_DESCRIPTION("PiNet: A Minimal Virtual Network Driver");
 
 static struct net_device *pinet_dev;
 
 /* ---- Transmit Packet ---- */
 static netdev_tx_t pinet_tx(struct sk_buff *skb, struct net_device *dev) {
	 pr_info("PiNet: Transmitting packet, length: %u bytes\n", skb->len);
	 dev_kfree_skb(skb); // Just free the skb (no actual transmission)
	 dev->stats.tx_packets++;
	 dev->stats.tx_bytes += skb->len;
	 return NETDEV_TX_OK;
 }
 
 /* ---- Open Device ---- */
 static int pinet_open(struct net_device *dev) {
	 pr_info("PiNet: Device opened\n");
	 netif_start_queue(dev);
	 return 0;
 }
 
 /* ---- Stop Device ---- */
 static int pinet_stop(struct net_device *dev) {
	 pr_info("PiNet: Device stopped\n");
	 netif_stop_queue(dev);
	 return 0;
 }
 
 /* ---- Stats ---- */
 static struct net_device_stats* pinet_get_stats(struct net_device *dev) {
	 return &dev->stats;
 }
 
 /* ---- Net Device Ops ---- */
 static const struct net_device_ops pinet_netdev_ops = {
	 .ndo_open       = pinet_open,
	 .ndo_stop       = pinet_stop,
	 .ndo_start_xmit = pinet_tx,
	 .ndo_get_stats  = pinet_get_stats,
 };
 
 /* ---- Init Function ---- */
 static void pinet_setup(struct net_device *dev) {
	 ether_setup(dev);
	 dev->netdev_ops = &pinet_netdev_ops;
	 dev->flags |= IFF_NOARP;
	 dev->features |= NETIF_F_HW_CSUM;
	 dev->tx_queue_len = 1000;
	 memcpy(dev->dev_addr, "\0PiNet", ETH_ALEN); // Make it unique
 }
 
 /* ---- Module Init ---- */
 static int __init pinet_init(void) {
	 pr_info("PiNet: Initializing\n");
	 pinet_dev = alloc_netdev(0, "pinet%d", NET_NAME_UNKNOWN, pinet_setup);
	 if (!pinet_dev)
		 return -ENOMEM;
	 return register_netdev(pinet_dev);
 }
 
 /* ---- Module Exit ---- */
 static void __exit pinet_exit(void) {
	 pr_info("PiNet: Exiting\n");
	 if (pinet_dev) {
		 unregister_netdev(pinet_dev);
		 free_netdev(pinet_dev);
	 }
 }
 
 module_init(pinet_init);
 module_exit(pinet_exit);
 