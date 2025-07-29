import random

def simulate_zkp(trials=20, knows_password=False):
    success_count = 0
    for _ in range(trials):
        path_entered = random.choice(['A', 'B'])       # Alice randomly picks a path
        challenge = random.choice(['A', 'B'])           # Bob randomly asks her to appear from A or B

        if knows_password:
            success = True                              # If Alice knows the secret, she always succeeds
        else:
            success = path_entered == challenge         # Without the secret, success is only if guess matches

        if success:
            success_count += 1

    print(f"Successful responses: {success_count}/{trials}")
    print(f"Success probability: {success_count/trials:.2f}")

# Simulate for a malicious prover (without the password)
simulate_zkp(trials=20, knows_password=False)
