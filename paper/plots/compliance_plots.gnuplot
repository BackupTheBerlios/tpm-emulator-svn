reset
#set terminal pdf enhanced
set terminal postscript eps color #enhanced
set size 0.5, 2
set origin 0.0, 0.0
set lmargin 3
set tmargin 1
set rmargin 3
set bmargin 12

set output "compliance.eps"
set ylabel "Number of TPM commands per function block"
set xtics nomirror rotate by 90
set noytics
set y2tics rotate by 90 
set yrange [0:17]
set xrange [-0.5:10.5]
set style data histogram
set style histogram rowstacked
set style fill solid border -1
set boxwidth 0.6
set nokey

set multiplot
set size 0.5, 1
set origin 0, 0
plot 'tpm_compliance.txt' index 0 using ($4):xticlabel(1) lt 2 fill solid 0.25 title "implemented and verified", \
     'tpm_compliance.txt' index 0 using ($3-$4)           lt 3 fill pattern 10 title "only partly implemented or not verified",\
     'tpm_compliance.txt' index 0 using ($2-$3)           lt 1 fill pattern  6 title "not implemented"
set origin 0, 1
plot 'tpm_compliance.txt' index 1 using ($4):xticlabel(1) lt 2 fill solid 0.25 title "implemented and verified", \
     'tpm_compliance.txt' index 1 using ($3-$4)           lt 3 fill pattern 10 title "only partly implemented or not verified",\
     'tpm_compliance.txt' index 1 using ($2-$3)           lt 1 fill pattern  6 title "not implemented"
set nomultiplot

set output "compliance_key.eps"
set lmargin 8
set tmargin 5
set rmargin 0
set bmargin 0
set border 0
set noylabel
set noxtics
set noytics
set noy2tics
set size 0.5, 0.11
set key reverse Left over nobox
plot  'tpm_compliance.txt' index 1 using (0):xticlabel(1) lt 2 fill solid 0.25 title "implemented and verified", \
      'tpm_compliance.txt' index 1 using (0)              lt 3 fill pattern 10 title "only partly implemented or not verified",\
      'tpm_compliance.txt' index 1 using (0)              lt 1 fill pattern  6 title "not implemented yet"

# plot 'tpm_compliance.txt' using ($4*100.0/$2):xticlabel(1) ls 1 title "implemented and verified", \
#     'tpm_compliance.txt' using (($3-$4)*100.0/$2)         ls 2 title "only partly implemented or not verified",\
#     'tpm_compliance.txt' using (($2-$3)*100.0/$2)         ls 3 title "not implemented"

