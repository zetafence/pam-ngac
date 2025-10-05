import random
import time
import csv
import networkx as nx

traversal_count = 0

def generate_abac_model(num_users, num_roles, num_resources):
    all_permissions = [
        'iam:PassRole', 'ec2:RunInstances', 's3:PutObject',
        'iam:AttachRolePolicy', 'iam:UpdateRole', 'iam:UpdateAssumeRolePolicy'
    ]

    users = {f"User_{i}": {'JobTitle': random.choice(['Developer', 'DataEngineer', 'SecurityAdmin'])} for i in range(num_users)}
    roles = {f"Role_{i}": {'Permissions': random.choices(all_permissions, k=random.randint(1, len(all_permissions)))} for i in range(num_roles)}
    resources = {f"Resource_{i}": random.choice(['EC2Instance', 'S3Bucket', 'IAMRole']) for i in range(num_resources)}
    policies = {}
    ground_truth_paths = {}

    G = nx.DiGraph()

    # Add Users, Roles, and Resources to Graph
    for user in users:
        G.add_node(user, type='User')
    for role, data in roles.items():
        G.add_node(role, type='Role', permissions=data['Permissions'])
    for resource, res_type in resources.items():
        G.add_node(resource, type=res_type)

    # Generate user-role associations
    for user, attributes in users.items():
        policies[user] = random.sample(list(roles.keys()), random.randint(1, 3))
        for role in policies[user]:
            G.add_edge(user, role)

    # Inject known valid paths (Ground Truth)
    for i in range(max(1, num_users // 20)):  # Create at least one ground truth path
        user = random.choice(list(users.keys()))
        role_A = f"Role_GT_A_{i}"
        role_B = f"Role_GT_B_{i}"
        resource = f"Resource_GT_{i}"

        # Add the new special roles and resources directly to the graph
        roles[role_A] = {'Permissions': ['iam:PassRole']}
        roles[role_B] = {'Permissions': ['ec2:RunInstances']}
        resources[resource] = 'IAMRole'

        G.add_node(role_A, type='Role', permissions=roles[role_A]['Permissions'])
        G.add_node(role_B, type='Role', permissions=roles[role_B]['Permissions'])
        G.add_node(resource, type='IAMRole')

        G.add_edge(user, role_A)  # Link user to role_A
        G.add_edge(role_A, resource)  # Link role_A to resource
        G.add_edge(resource, role_B)  # Link resource to role_B

        # Record ground truth paths
        ground_truth_paths[user] = (role_A, resource, role_B)

    return users, roles, resources, policies, ground_truth_paths, G

def detect_privilege_escalation(G):
    global traversal_count
    escalation_paths = {}

    for user in [n for n, d in G.nodes(data=True) if d['type'] == 'User']:
        for role in G.successors(user):
            if G.nodes[role]['type'] == 'Role':
                for resource in G.successors(role):
                    if G.nodes[resource]['type'] == 'IAMRole':
                        if 'iam:PassRole' in G.nodes[role]['permissions']:
                            for next_role in G.successors(resource):
                                if G.nodes[next_role]['type'] == 'Role' and 'ec2:RunInstances' in G.nodes[next_role]['permissions']:
                                    escalation_paths[user] = (role, resource, next_role)
                                    break

    return escalation_paths

def run_privilege_escalation_simulation(log_ranges, repetitions=10):
    results = []

    for _ in range(repetitions):
        for num_users, num_roles, num_resources in log_ranges:
            global traversal_count
            traversal_count = 0

            users, roles, resources, policies, ground_truth_paths, G = generate_abac_model(num_users, num_roles, num_resources)

            start_time = time.time()
            detected_paths = detect_privilege_escalation(G)
            detection_time = time.time() - start_time

            # Compare detected paths with ground truth
            true_positives = len([user for user in detected_paths if user in ground_truth_paths])
            false_positives = len([user for user in detected_paths if user not in ground_truth_paths])
            false_negatives = len([user for user in ground_truth_paths if user not in detected_paths])

            fpr = false_positives / max(1, false_positives + true_positives)
            fnr = false_negatives / max(1, len(ground_truth_paths))

            graph_size = G.number_of_nodes() + G.number_of_edges()

            results.append([num_users, num_roles, num_resources, fpr, fnr, detection_time, graph_size])

    csv_file = '/tmp/abac_privilege_escalation_fpr_fnr_fixed_v2_results.csv'
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Num_Users', 'Num_Roles', 'Num_Resources', 'FPR', 'FNR', 'Detection_Time', 'Graph_Size'])
        for row in results:
            writer.writerow(row)

    return csv_file


if __name__ == "__main__":
    log_ranges = [
        (100, 20, 30), (200, 40, 60), (400, 80, 120), (800, 160, 240),
        (1000, 200, 300), (2000, 400, 600), (4000, 800, 1200),
        (6000, 1200, 1800), (8000, 1600, 2400), (10000, 2000, 3000)
    ]
    run_privilege_escalation_simulation(log_ranges, repetitions=10)

