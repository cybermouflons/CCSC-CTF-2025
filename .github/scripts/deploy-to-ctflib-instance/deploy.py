#!/usr/bin/env python3
import os
import subprocess
import yaml

def prompt_yes_no(question):
    while True:
        ans = input(f"{question} (y/n): ").strip().lower()
        if ans in ['y', 'yes']:
            return True
        elif ans in ['n', 'no']:
            return False
        else:
            print("Please answer with y or n.")

def process_challenges(root_dir, do_install, build_dockers):
    for category in os.listdir(root_dir):
        category_path = os.path.join(root_dir, category)
        if not os.path.isdir(category_path):
            continue

        # skip hidden folders
        if category_path.startswith('./.'):
            continue

        for challenge in os.listdir(category_path):
            challenge_path = os.path.join(category_path, challenge)
            if not os.path.isdir(challenge_path):
                continue

            challenge_yml_path = os.path.join(challenge_path, 'challenge.yml')
            if not os.path.isfile(challenge_yml_path):
                print(f"WARNING: challenge.yml not found in {challenge_path}")
                continue

            # Read challenge.yml
            with open(challenge_yml_path, 'r') as f:
                try:
                    challenge_data = yaml.safe_load(f)
                except yaml.YAMLError as e:
                    print(f"ERROR parsing {challenge_yml_path}: {e}")
                    continue

            challenge_type = challenge_data.get('type')
            rel_path = os.path.relpath(challenge_path, root_dir)

            if challenge_type == "docker-dynamic":
                if build_dockers:
                    cmd = ["make"]
                    print(f"Packing image: {' '.join(cmd)}")
                    subprocess.run(cmd, cwd=challenge_path)
                    cmd = ["ctf", "plugins", "docker_challenge_deploy", rel_path]
                    print(f"Running: {' '.join(cmd)}")
                    subprocess.run(cmd)
                if do_install: # install
                    cmd = ["ctf", "challenge", "install", rel_path]
                    print(f"Running: {' '.join(cmd)}")
                    subprocess.run(cmd)
                else:  # sync
                    cmd = ["ctf", "challenge", "sync", rel_path]
                    print(f"Running: {' '.join(cmd)}")
                    subprocess.run(cmd)

            elif challenge_type == "dynamic":
                if do_install: # install
                    cmd = ["ctf", "challenge", "install", rel_path]
                    print(f"Running: {' '.join(cmd)}")
                    subprocess.run(cmd)
                else:  # sync
                    cmd = ["ctf", "challenge", "sync", rel_path]
                    print(f"Running: {' '.join(cmd)}")
                    subprocess.run(cmd)

            else:
                print(f"WARNING: Unknown challenge type '{challenge_type}' in {challenge_yml_path}")

if __name__ == "__main__":

    # Ask user what to do upfront
    do_install = prompt_yes_no("Do you want to install challenges?")
    build_dockers = prompt_yes_no("Do you want to build dockers?")

    # Process
    process_challenges(".", do_install, build_dockers)
