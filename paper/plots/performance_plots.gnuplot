# gnuplot
reset
set terminal postscript eps color enhanced

set style line 1 lt 1 lw 3
set style line 2 lt 2 lw 3
set style line 3 lt 3 lw 3
set style line 4 lt 4 lw 3
set style line 5 lt 5 lw 3
set style line 6 lt 6 lw 3
set style line 9 lt -1 lw 1

max(a,b) = a > b ? a : b
min(a,b) = a < b ? a : b

#set size 0.65, 0.65
set size 0.65, 0.65
set lmargin 6
set tmargin 2
set rmargin 6
set bmargin 3

set output "duration_self_test.eps"
set title "Duration (in sec) to execute TPM\\_SelfTest on each TPM emulator instance"
set xlabel "Number of concurrently executed TPM emulator instances."
set yrange [0:*]
set xrange [1:500]
set ytics 20
set style data points
plot "data_self_test.txt" using 1:2 with linespoints ls 1 notitle
set ytics auto

set output "duration_extend.eps"
set title "Duration (in sec) to execute TPM\\_Extend on each TPM emulator instance"
set xlabel "Number of concurrently executed TPM emulator instances."
set yrange [0:*]
set xrange [1:500]
set ytics 0.005
set style data points
plot "data_extend.txt" using 1:2 with linespoints ls 1 notitle
set ytics auto

set size 1, 0.66
set lmargin 6
set tmargin 2
set rmargin 2
set bmargin 2

set output "performance_comparison.eps"
set multiplot
set title "Duration (in sec) to execute a TPM command"
set xlabel ""
set yrange [1e-4:20]
set xrange [-1:9]
set logscale y
set format y "10^{%L}"
set style fill solid border -1
set xtics ("TPM\\_SelfTestFull" 0, "TPM\\_TakeOwnership" 2, "TPM\\_Extend" 4, "TPM\\_CreateWrapKey" 6, "TPM\\_Sign" 8)
plot 'execution_time.data' using (2*$2-0.25):3:(0.5) with boxes fill solid 0.25 lt 2 title "Hardware TPM", \
     'execution_time.data' using (2*$2+0.25):5:(0.5) with boxes fill pattern 10 lt 1 title "TPM Emulator"
# set style data points
# set pointsize 0.1
# plot 'execution_time.data' using (2*$2-0.25):3:4 with yerrorbars notitle ls 9, \
#      'execution_time.data' using (2*$2+0.25):5:6 with yerrorbars notitle ls 9
unset multiplot

set size 1, 0.66
set lmargin 6
set tmargin 2
set rmargin 2
set bmargin 2

set output "performance_comparison2.eps"
set multiplot
set title "Duration (in sec) to execute a TPM command"
set xlabel ""
set yrange [1e-4:20]
set xrange [-1:9]
set logscale y
set format y "10^{%L}"
set style fill solid border -1
set xtics ("TPM\\_SelfTestFull" 0, "TPM\\_Extend" 2, "TPM\\_DAA\\_Join" 4)
plot 'execution_time2.data' using (2*$2-0.25):3:(0.5) with boxes fill solid 0.25 lt 2 title "Hardware TPM", \
     'execution_time2.data' using (2*$2+0.25):5:(0.5) with boxes fill pattern 10 lt 1 title "TPM Emulator"
unset multiplot
