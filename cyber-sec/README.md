# COS30049, Assignment 3 - Cyber Security
## Threat Model:
### Possible Attackers
* Phishing scammers targeting wide groups of vulnerable people, typically people of low digital literacy.
* Bad actors targeting specific organisations that use the detection tool, aiming to get credentials of members and breach their security
### Attack objectives
Attackers will target the phishing tool to find exploits or weaknesses in the detection tool (e.g. bias towards certain TLDs, URL lengths, etc) so they can create phishing links that pass through the tool with a high legitimacy score.
### Attacker methods
Simple methods attackers may try to acheive this might include manual or automated testing on our model to find what attributes of URLs can be changed so they can pass as legtimate URLs. Similar methods can also be used for model extraction, which involves recording responses from the model and training an attacker owned model to behave as similar to the targeted model as possible. This new model can then be distributed by the attacker so they and others may try and find weaknesses in it that may also be present in the original model.\
Notably, both of these attacks require making many queries to the API of the model to investigate its behaviour/reponses. These attacks can therefore be mitigated with rate limiting on API queries.
##