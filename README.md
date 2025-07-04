
# Arahant

Arahant is a PRM in a EER environment. It was conceived as an exclusive approach for special flows and services that need full performance of the network and are considered worth spending more energy
## Prerequisites

Before running Arahant, ensure that you have the following installed:

- **Mininet**: Required for running the network simulations.
- **RYU**: A component-based SDN controller that is essential for running Arahant.

## Installing Mininet

To install Mininet, follow the official [Mininet installation guide](http://mininet.org/download/).

## Installing RYU

For recent Ubuntu versions, follow these steps to install RYU:

1. Add the necessary repository:
   ```bash
   sudo add-apt-repository ppa:deadsnakes/ppa
   ```

2. Install `python3.9` and `virtualenv`:
   ```bash
   sudo apt-get install virtualenv python3.9 python3.9-distutils
   ```

3. Create a virtual environment with Python 3.9:
   ```bash
   virtualenv -p`which python3.9` ryu-python3.9-venv
   ```

4. Activate the virtual environment:
   ```bash
   source ryu-python3.9-venv/bin/activate
   ```

5. Confirm you are in the virtual environment:
   ```bash
   echo $VIRTUAL_ENV
   ```

6. Install RYU:
   ```bash
   pip install ryu
   ```

7. Fix eventlet compatibility issues by adjusting the version:
   ```bash
   pip uninstall eventlet
   pip install eventlet==0.30.2
   ```

8. Verify that RYU is installed:
   ```bash
   ryu-manager --help
   ```

Once RYU is installed, you'll be ready to run Arahant.

## Running Arahant

Follow these steps to run Arahant:


1. Activate the RYU virtual environment:
   ```bash
   source ryu-python3.9-venv/bin/activate
   ```

2. Go to the Arahant folder and start the RYU controller with Arahant:
   ```bash
   ryu-manager --observe-links Arahant.py
   ```

3. In a new terminal, navigate to the `Arahant` folder and start the network topology:
   ```bash
   sudo python ./fattree.py
   ```

### Done!

Arahant is now up and running! You can begin simulating network traffic and monitor how Arahant optimizes your network performance.
