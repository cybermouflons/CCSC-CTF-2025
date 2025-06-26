#!/usr/bin/env python3
import os
import shutil

def process_challenges(root_dir):
    for category in os.listdir(root_dir):
        category_path = os.path.join(root_dir, category)
        if not os.path.isdir(category_path):
            continue

        for challenge in os.listdir(category_path):
            challenge_path = os.path.join(category_path, challenge)
            if not os.path.isdir(challenge_path):
                continue

            challenge_yml = os.path.join(challenge_path, 'challenge.yml')
            challenge_ctflib_yml = os.path.join(challenge_path, 'challenge.ctflib.yml')

            if not os.path.exists(challenge_yml) or not os.path.exists(challenge_ctflib_yml):
                continue

            if os.path.exists(challenge_ctflib_yml):
                print(f"Replacing {challenge_yml} with {challenge_ctflib_yml}")
                shutil.copyfile(challenge_ctflib_yml, challenge_yml)

if __name__ == "__main__":
    process_challenges(".")
