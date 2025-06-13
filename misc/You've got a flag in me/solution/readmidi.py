import pretty_midi

K = [7,58,391,58,129,80,537,80,389,33,80,107,522,391,389,148,386,522,389,58,240,240,107,1]

midi_data = pretty_midi.PrettyMIDI("../public/flag.midi")
instrument = pretty_midi.Instrument(program=0)  

notes=""
for instrument in midi_data.instruments:
	if instrument.program==0: #Acoustic Grand Piano
		for note in instrument.notes:
			notes += chr(note.pitch)

for k in K:
	print(notes[k],end="")
	
'''
#flag = "ECSC{M1D1_F1L3S_4R3_C00L!}"
for f in flag:
	for i,note in enumerate(notes):
		if note==f:
			print(i)
			break
'''