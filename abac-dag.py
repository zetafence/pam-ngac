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

    return users, roles, resources, policies, G

def build_abac_graph(G, roles, resources):
    for role, role_data in roles.items():
        for resource in resources:
            if resources[resource] == 'EC2Instance' and 'ec2:RunInstances' in role_data['Permissions']:
                G.add_edge(role, resource)
            if resources[resource] == 'IAMRole' and 'iam:PassRole' in role_data['Permissions']:
                G.add_edge(role, resource)

    return G

def detect_privilege_escalation(G):
    global traversal_count
    traversal_count = 0
    escalation_paths = {}

    for user in [n for n, d in G.nodes(data=True) if d['type'] == 'User']:
        for role in G.successors(user):
            if G.nodes[role]['type'] == 'Role':
                traversal_count += 1  # Count user to role traversal
                for resource in G.successors(role):
                    if G.nodes[resource]['type'] == 'IAMRole':
                        if 'iam:PassRole' in G.nodes[role]['permissions']:
                            traversal_count += 1  # Count role to IAMRole traversal
                            for next_role in G.successors(resource):
                                if G.nodes[next_role]['type'] == 'Role' and 'ec2:RunInstances' in G.nodes[next_role]['permissions']:
                                    escalation_paths[user] = (role, resource, next_role)
                                    traversal_count += 1  # Count IAMRole to Role traversal
                                    break

    return escalation_paths, traversal_count

def run_privilege_escalation_simulation(log_ranges, repetitions=10):
    results = []

    for _ in range(repetitions):
        for num_users, num_roles, num_resources in log_ranges:

            start_time = time.time()
            users, roles, resources, policies, G = generate_abac_model(num_users, num_roles, num_resources)
            build_time = time.time() - start_time

            G = build_abac_graph(G, roles, resources)

            start_time = time.time()
            detected_paths, traversal_frequency = detect_privilege_escalation(G)
            detection_time = time.time() - start_time

            graph_size = G.number_of_nodes() + G.number_of_edges()

            results.append([num_users, num_roles, num_resources, traversal_frequency, detection_time, graph_size, build_time])

    csv_file = '/tmp/abac_privilege_escalation_traversal_frequency_results.csv'
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Num_Users', 'Num_Roles', 'Num_Resources', 'Traversal_Frequency', 'Detection_Time', 'Graph_Size', 'Graph_Build_Time'])
        for row in results:
            writer.writerow(row)

    return csv_file


if __name__ == "__main__":
    log_ranges = [
        (100, 20, 30),
        (200, 40, 60),
        (400, 80, 120),
        (600, 100, 180),
        (800, 160, 240),
        (1000, 200, 300),
        (2000, 400, 600),
    ]
    run_privilege_escalation_simulation(log_ranges, repetitions=10)
