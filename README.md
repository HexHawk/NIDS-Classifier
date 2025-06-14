# 🛡️ NIDS Classifier 

[![Python](https://img.shields.io/badge/python-v3.9+-blue.svg)](https://www.python.org/)
[![Gradio](https://img.shields.io/badge/Gradio-3.x-orange.svg)](https://gradio.app/)
[![NSL-KDD](https://img.shields.io/badge/Dataset-NSL--KDD-green.svg)](https://www.unb.ca/cic/datasets/nsl.html)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A machine learning-based network traffic classifier built using the NSL-KDD dataset. This project implements a Network Intrusion Detection System (NIDS) that can classify network traffic as benign or malicious.

## 🚀 Features

- 🔍 Real-time network traffic classification
- 📊 Interactive visualization of results
- 💾 Export functionality for classified data
- 📈 Feature importance analysis
- 🎯 Built on the NSL-KDD dataset

## 🛠️ Installation

1. Clone the repository:

```bash
git clone https://github.com/HexHawk/NIDS-Classifier.git
cd NIDS-Classifier
```

2. Create and activate a virtual environment (optional but recommended):

```bash
python -m venv nids_env
source nids_env/bin/activate  # On Windows: nids_env\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Download the NSL-KDD dataset:
   - Download `KDDTrain+.txt` from [NSL-KDD dataset](https://www.unb.ca/cic/datasets/nsl.html)
   - Place it in the project root directory

## 🚀 Usage

1. Start the application:

```bash
python app.py
```

2. Access the web interface at `http://127.0.0.1:7860`

3. Upload your network traffic CSV file (must contain NSL-KDD features)

4. Click "Classify" to analyze the traffic

## 📊 Data Format

Your input CSV must contain the following NSL-KDD features:

### 🌐 Basic Connection Features

These features are derived from packet-level network connection attributes:

| Feature        | Description                                            | Type        |
| -------------- | ------------------------------------------------------ | ----------- |
| duration       | Length of connection (seconds)                         | numeric     |
| protocol_type  | Type of protocol (tcp, udp, icmp)                      | categorical |
| service        | Network service (http, ftp, etc.)                      | categorical |
| flag           | Connection status                                      | categorical |
| src_bytes      | Bytes sent from source to destination                  | numeric     |
| dst_bytes      | Bytes sent from destination to source                  | numeric     |
| land           | 1 if connection is from/to same host/port; 0 otherwise | binary      |
| wrong_fragment | Number of wrong fragments                              | numeric     |
| urgent         | Number of urgent packets                               | numeric     |

### 💻 Content Features

These features look for suspicious behavior in the data portion:

| Feature            | Description                                           | Type    |
| ------------------ | ----------------------------------------------------- | ------- |
| hot                | Number of "hot" indicators                            | numeric |
| num_failed_logins  | Number of failed login attempts                       | numeric |
| logged_in          | 1 if successfully logged in; 0 otherwise              | binary  |
| num_compromised    | Number of compromised conditions                      | numeric |
| root_shell         | 1 if root shell is obtained; 0 otherwise              | binary  |
| su_attempted       | 1 if "su root" command attempted; 0 otherwise         | binary  |
| num_root           | Number of root accesses                               | numeric |
| num_file_creations | Number of file creation operations                    | numeric |
| num_shells         | Number of shell prompts                               | numeric |
| num_access_files   | Number of operations on access control files          | numeric |
| num_outbound_cmds  | Number of outbound commands in an ftp session         | numeric |
| is_host_login      | 1 if the login belongs to the "hot" list; 0 otherwise | binary  |
| is_guest_login     | 1 if the login is a guest login; 0 otherwise          | binary  |

### 🕒 Time-based Traffic Features

These features capture properties within a time window:

| Feature            | Description                                             | Type    |
| ------------------ | ------------------------------------------------------- | ------- |
| count              | Number of connections to same host in past 2 seconds    | numeric |
| srv_count          | Number of connections to same service in past 2 seconds | numeric |
| serror_rate        | % of connections with SYN errors                        | numeric |
| srv_serror_rate    | % of connections with SYN errors (same service)         | numeric |
| rerror_rate        | % of connections with REJ errors                        | numeric |
| srv_rerror_rate    | % of connections with REJ errors (same service)         | numeric |
| same_srv_rate      | % of connections to same service                        | numeric |
| diff_srv_rate      | % of connections to different services                  | numeric |
| srv_diff_host_rate | % of connections to different hosts                     | numeric |

### 🌍 Host-based Traffic Features

These features examine established connections:

| Feature                     | Description                                       | Type    |
| --------------------------- | ------------------------------------------------- | ------- |
| dst_host_count              | Count of connections having same destination host | numeric |
| dst_host_srv_count          | Count of connections having same port             | numeric |
| dst_host_same_srv_rate      | % of connections having same service              | numeric |
| dst_host_diff_srv_rate      | % of different services                           | numeric |
| dst_host_same_src_port_rate | % of connections having same source port          | numeric |
| dst_host_srv_diff_host_rate | % of connections to different hosts               | numeric |
| dst_host_serror_rate        | % of connections with SYN errors                  | numeric |
| dst_host_srv_serror_rate    | % of connections with SYN errors (same service)   | numeric |
| dst_host_rerror_rate        | % of connections with REJ errors                  | numeric |
| dst_host_srv_rerror_rate    | % of connections with REJ errors (same service)   | numeric |

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
