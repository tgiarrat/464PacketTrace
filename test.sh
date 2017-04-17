make trace
./trace TraceFiles/ArpTest.pcap > myoutput.out
diff myoutput.out TraceFiles/ArpTest.out
echo "Arp Test Done"
./trace TraceFiles/PingTest.pcap > myoutput.out
diff myoutput.out TraceFiles/PingTest.out
echo "Ping Test Done"
./trace TraceFiles/UDPfile.pcap > myoutput.out
diff myoutput.out TraceFiles/UDPfile.out
echo "UDP Test Done"
./trace TraceFiles/smallTCP.pcap > myoutput.out
diff myoutput.out TraceFiles/smallTCP.out
echo "Small TCP Done"
./trace TraceFiles/Http.pcap > myoutput.out
diff myoutput.out TraceFiles/Http.out
echo "Http Done"
./trace TraceFiles/largeMix.pcap > myoutput.out
diff myoutput.out TraceFiles/largeMix.out
echo "largeMix Done"
rm myoutput.out
./trace TraceFiles/largeMix2.pcap > myoutput.out
diff myoutput.out TraceFiles/largeMix2.out
echo "largeMix2 Done"
rm myoutput.out
./trace TraceFiles/IP_bad_checksum.pcap > myoutput.out
diff myoutput.out TraceFiles/IP_bad_checksum.out
echo "Bad IP Done"
./trace TraceFiles/TCP_bad_checksum.pcap > myoutput.out
diff myoutput.out TraceFiles/TCP_bad_checksum.out
echo "Bad TCP Done"
rm myoutput.out
make clean