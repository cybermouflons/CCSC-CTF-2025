import string
import random
import signal
import sys

from manchester import Manchester
from nrzi import NRZI
from hamming74 import Hamming
from uart import UART

# ANSI color codes for a friendlier UI
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

WELCOME = f"""
{Colors.HEADER}{Colors.BOLD}
 ____       _     ____                  _ 
|  _ \ ___ | |_  |  _ \ ___  _   _ _ __(_)
| |_) / _ \| __| | |_) / _ \| | | | '__| |
|  __/ (_) | |_  |  __/ (_) | |_| | |  | |
|_|   \___/ \__| |_|   \___/ \__,_|_|  |_|


{Colors.ENDC}
Welcome to {Colors.OKBLUE}Pot Pouri Challenge{Colors.ENDC}!
Decode 100 randomized messages encoded with various schemes.
Protocols you'll see:
  - NRZ-I
  - Manchester
  - Hamming (7,4)
  - UART

Type your decoded ASCII message when prompted. You have {Colors.WARNING}1 seconds{Colors.ENDC} per round.
Good luck!

Let me give you an example to get started:

[Round 1/100] [Manchester] 01101001100101010110100101100110011010011010010101101001101001010110100110101010
> hello
{Colors.OKGREEN}Correct!{Colors.ENDC}
"""

FLAG = 'ECSC{example-flag}'
if os.path.exists('flag.txt'):
    FLAG = open('flag.txt', 'r').read().strip()


def get_encoders():
    return {
        'UART': UART(data_bits=8, parity=True).encode,
        'Hamming74': Hamming().encode,
        'Manchester': Manchester().encode,
        'NRZI': NRZI(initial_level=0).encode,
    }


def random_message(max_len=8) -> str:
    length = random.randint(1, max_len)
    alphabet = string.ascii_letters + string.digits
    return ''.join(random.choice(alphabet) for _ in range(length))


def timed_input(timeout: int) -> str:
    def handler(signum, frame):
        raise TimeoutError

    signal.signal(signal.SIGALRM, handler)
    signal.alarm(timeout)
    try:
        line = input("> ")
        signal.alarm(0)
        return line
    except TimeoutError:
        signal.alarm(0)
        return None


def main():
    print(WELCOME)
    encoders = get_encoders()

    for i in range(2, 101):
        message = random_message(8)
        protocol = random.choice(list(encoders.keys()))
        encode_fn = encoders[protocol]
        encoded = encode_fn(message)

        print(f"[Round {i}/100] [{protocol}] {encoded}")

        answer = timed_input(1)
        if answer is None:
            print(f"\n{Colors.FAIL}Time out! Session terminated.{Colors.ENDC}")
            sys.exit(1)

        if answer.strip() != message:
            print(f"{Colors.FAIL}Wrong! Session terminated.{Colors.ENDC}")
            sys.exit(1)

        print(f"{Colors.OKGREEN}Correct!{Colors.ENDC}\n")

    print(FLAG)
    print(f"\n{FLAG}")



if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Interrupted by user. Goodbye!{Colors.ENDC}")
        sys.exit(0)
