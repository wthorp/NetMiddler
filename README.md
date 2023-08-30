# NetMiddler
An incomplete HTTP(S) man-in-the-middle library akin to Fiddler.

Hence, the goal is to intercept HTTP(S) requests via an HTTP(S) proxy.
HTTPS is the hard part, as it requires a man-in-the-middle attack to accomplish.
Like Fiddler, this attack is facilitated by creating a local CA Certificate trust.
The code relies "github.com/smallstep/truststore" to reg for Java, Firefox, and the local operatings system.

This is a work in progress, and doesn't fully function yet
If you're looking for _working software_, check out [goproxy](https://github.com/elazarl/goproxy).