# LFP: Lightweight FingerPrint

LFP is a fingerprinting technique aims to identify the vendor of router. For more details please refer to our paper. 

# Quick Start 

We use Scamper version 20191102 to probe targets. To test it: 

- Run `run.sh` to probe a list of targets 
`./run.sh target-ips.txt target-ips.json`   

- Use `analysis.py` to analyze the responses and generate a fingerprint  
`python3 analysis.py target-ips.json`

The current set of signatures can be found in signatures directory 

# Bib
If you use LFP in your research, please reference it with the following citations:

```bibtex
@inproceedings{IMC2023-Fingerprinting,
	title = {{Illuminating Router Vendor Diversity Within Providers and Along Network Paths}},
	author = {Taha Albakour and Oliver Gasser and Robert Beverly and Georgios Smaragdakis},
	month = {October},
	year = {2023},
	booktitle = {Proceedings of ACM Internet Measurement Conference (IMC) 2023},
	address = {Montreal, QC, Canada}
}

```