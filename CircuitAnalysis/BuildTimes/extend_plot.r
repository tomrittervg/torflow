args = commandArgs()

e <- read.table(args[3]) 
pdf("extensiontimes2.pdf", width=8, height=6)
plot(density(e[,2] + e[,3] + e[,4]), ylim=c(0,0.8), xlim=c(0,10), frame=FALSE,
axes=FALSE, main="Circuit extension time", xlab="Time [s]")
axis(1, at=0:10)
axis(2)
lines(density(e[,2]), col="red")
lines(density(e[,3]), col="darkgreen")
lines(density(e[,4]), col="blue")
text(x=1.1, y=0.7, labels="1st hop", col="red")
text(x=2.65, y=0.55, labels="2nd hop", col="darkgreen")
text(x=3.68, y=0.27, labels="3rd hop", col="blue")
text(x=5.9, y=0.13, labels="All hops")
abline(v=1:10, lty=3)
dev.off()

