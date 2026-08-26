# Attack Scenario Reconstruction

This is a code repository for my master thesis on Attack Scenario Reconstruction. The repository contains four modules:

- The **Dataset Preprocessor**
- The **Scenario Reconstructor**
- The **Scenario Generator**
- The **Metrics collector**

The Dataset Preprocessor consists in a series of Jupyter notebooks which are responsible for transforming the initial intrusion detection dataset into a format suitable for scenario reconstruction. We started from the [cAPTure dataset](https://www.sciencedirect.com/science/article/pii/S1389128626005827) and extracted traffic data corresponding to the dollar_char campaign, which is then preprocessed to adapt it to our own reconstruction requirements. The results is a separated test and train set. The train set is used to build the necessary machine learners for reconstruction, while the test set is used as the basis for the reconstruction dataset through enrichment with anomaly and attack type score. 

The resulting dataset, which we call the event dataset, contain the network flows extracted from the corresponding campaign labeled with a corresponding anomaly and attack type score. This dataset can then be used by the Scenario Generator module to synthetically generate custom attack scenarios which can then be used for the purpose of metrics collection and reconstruction evaluation. To produce the target scenario through the Scenario Generator one must use its API and provide the requested parameters.  

From the results returned by the Scenario Generator module and the Scenario reconstructor module, the Metrics Collector is then able to compute and log performance and quality metrics of interest. Three types of metrics are provided: confusion matrix metrics which assess the influence that the reconstructor has on intrusion detection results, recall and precision metrics which assess the ability of the reconstructor in including individual anomalous events, and finally, soundness and completeness metrics which assess the reconstructor's ability in making correct associations between events.   

Lastly, the Scenario Reconstructor is the module responsible for transforming isolated alerts in explainable attack scenarios based on the current network state, the alert history and the attack's characteristics. The reconstructor models the system as a set of hosts, each with their compromise attributes describing attack relevant properties. When an alert is produced we assign an attack type to the alert based on its attack type scores and check the feasibility of the attack in the current network state: if the attack is feasible, the alert is added and the network state is modified accordingly, while if it is not we check the alert history and try to find false negative classifications.

At the end of the reconstruction procedure a sequence of attack steps is obtained from the reconstructor representing predicted attacker actions. The configuration of the Scenario Reconstructor happens through the definition of attack relevant host attributes based on the target network's properties and the types of attacks we are considering, and the pre- and post-conditions of the same attacks. These pre- and post-conditions are defined as assertions on the source or destination hosts of attacks regarding their compromise attributes.

For more detailed information on the structure and the configuration of the various modules see the thesis in question.  
