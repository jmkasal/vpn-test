import json
import random
from time import perf_counter


class IpPrefixTrie:
    class Node:
        def __init__(self):
            self.children = {}
            self.prefix_len = None
            self.route_name = None
            self.cidr = None
            self.routes = set()

    def __init__(self):
        self.root = self.Node()

    @staticmethod
    def enumerate_ending_addresses(network, mask):

        # Convert the network address to an integer
        network_parts = network.split('.')
        network_int = sum(int(octet) << (24 - 8 * i) for i, octet in enumerate(network_parts))

        # Calculate the number of addresses in the subnet
        num_addresses = 2 ** (32 - mask)

        # Generate all addresses in the subnet
        for i in range(num_addresses):
            yield network_int + i

    @staticmethod
    def prefix_to_closest_oct(prefix, mask):
        # Convert the prefix to an integer
        prefix_parts = prefix.split('.')
        prefix_int = sum(int(octet) << (24 - 8 * i) for i, octet in enumerate(prefix_parts))

        # Calculate the number of addresses in the subnet
        octet = mask // 8
        if mask % 8 == 0 and mask != 0:
            octet -= 1

        # Generate all addresses in the subnet
        for i in range(4):
            if i == octet:
                # we need to iterate through all prefixes between the start of the mask
                # and the next nearest multiple of 8
                mask_num = (prefix_int >> (24 - 8 * i)) & 0xFF
                parts = []
                for j in range(2 ** ((8 * (octet + 1)) - mask)):
                    # print(f"Octet {i} is the closest octet to the mask")
                    parts.append(mask_num + j)
                yield parts
                break
            else:
                # print(f"Octet {i} is not the closest octet to the mask")
                yield prefix_int >> (24 - 8 * i) & 0xFF

        # return [prefix_int + i for i in range(num_addresses)]

    def insert(self, ip_prefix, route_name=None):
        route = (ip_prefix, route_name)
        parts = ip_prefix.split('/')
        network, mask = parts[0], int(parts[1])
        node = self.root
        for part in self.prefix_to_closest_oct(network, mask):
            if type(part) is not list:
                if part not in node.children:
                    node.children[part] = self.Node()

                node = node.children[part]
            else:
                for prefix in part:
                    if prefix not in node.children:
                        match = self.Node()
                        match.prefix_len = mask
                        match.route_name = route_name
                        node.children[prefix] = match
                        node.children[prefix].cidr = ip_prefix
                        node.children[prefix].routes.add(route)
                    else:
                        node.children[prefix].routes.add(route)
                        if node.children[prefix].prefix_len is None or node.children[prefix].prefix_len < mask:
                            node.children[prefix].prefix_len = mask
                            node.children[prefix].route_name = route_name
                            node.children[prefix].cidr = ip_prefix

    def remove(self, ip_prefix, route_name):
        node = self.root
        parts = ip_prefix.split('/')
        network, mask = parts[0], int(parts[1])
        potential_matches = []
        for part in self.prefix_to_closest_oct(network, mask):
            if type(part) is not list:
                if part not in node.children:
                    return
                node = node.children[part]
                potential_matches.append(node)
            else:
                for prefix in part:
                    if prefix not in node.children:
                        return
                    match = node.children[prefix]
                    match.routes.remove((ip_prefix, route_name))
                    prefix_len = -1
                    for r in match.routes:
                        if r[1] is not None:
                            prefix_len = max(prefix_len, int(r[0].split('/')[1]))
                            match.prefix_len = prefix_len
                            match.route_name = r[1]
                            match.cidr = r[0]

        for match in reversed(potential_matches):
            to_delete = []
            for key, value in match.children.items():
                if not value.routes and not value.children:
                    to_delete.append(key)
            for key in to_delete:
                match.children.pop(key)

    def search(self, ip):
        node = self.root
        for addr in self.enumerate_ending_addresses(ip, 32):
            best_match = -1, None, None
            for i in range(4):
                char = (addr >> (24 - 8 * i)) & 0xFF
                if char not in node.children:
                    break

                node = node.children[char]
                if node.prefix_len is not None and node.prefix_len > best_match[0]:
                    best_match = node.prefix_len, node.cidr, node.route_name,

            if best_match[0] != -1:
                return best_match
        return None


def network_to_int(network, mask):
    parts = network.split('.')
    return sum(int(octet) << (24 - 8 * i) for i, octet in enumerate(parts)) >> (32 - mask)


def int_to_network(network_addr, mask):
    parts = []
    for i in range(4):
        part = (network_addr >> (24 - 8 * i)) & 0xFF
        parts.append(str(part))
    # parts.reverse()
    return '.'.join(parts) + f'/{mask}'


class NaiveIpPrefix:
    def __init__(self):
        self.prefixes = []

    def insert(self, ip_prefix, route_name=None):
        parts = ip_prefix.split('/')
        network, mask = parts[0], int(parts[1])
        self.prefixes.append((network_to_int(network, mask) << (32 - mask), mask, route_name))

    def search(self, ip):
        ip_parts = ip.split('.')
        ip_int = sum(int(octet) << (24 - 8 * i) for i, octet in enumerate(ip_parts))
        best_match = None
        for prefix, mask, route_name in self.prefixes:
            if ip_int & ((0xFFFFFFFF >> (32 - mask)) << (32 - mask)) == prefix:
                if best_match is None or mask > best_match[1]:
                    best_match = (prefix, mask, route_name)

        return best_match


class Rule:

    def __init__(self, src_ip: str, dest_ip: str, protocol: str, dest_port: int, rule_name: str, action='allow'):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.protocol = protocol
        self.port = dest_port
        self.rule_name = rule_name
        self.action = action


class PortMatcher:

    def __init__(self):
        self.ports = {}

    def insert(self, port, rule_name):
        self.ports[port] = self.ports.get(port, [rule_name]) + [rule_name]

    def search(self, port):
        return port, self.ports.get(port, None)


class ProtocolMatcher:

        def __init__(self):
            self.protocols = {}

        def insert(self, protocol, rule_name):
            self.protocols[protocol] = self.protocols.get(protocol, [rule_name]) + [rule_name]

        def search(self, protocol):
            return protocol, self.protocols.get(protocol)


class PacketClassifier:

    def __init__(self):
        self.cross_product = {}
        self.src_ip_matcher = IpPrefixTrie()
        self.dest_ip_matcher = IpPrefixTrie()
        self.protocol_matcher = ProtocolMatcher()
        self.port_matcher = PortMatcher()
        self.rules = []

    def insert(self, rule: Rule):
        self.rules.append(rule)
        self.src_ip_matcher.insert(rule.src_ip, rule.rule_name)
        self.dest_ip_matcher.insert(rule.dest_ip, rule.rule_name)
        self.protocol_matcher.insert(rule.protocol, rule.rule_name)
        self.port_matcher.insert(rule.port, rule.rule_name)

    def find_best_match(self, f1, f2, f3, f4):
        longest_src = self.src_ip_matcher.search(f1)[1]
        longest_dest = self.dest_ip_matcher.search(f2)[1]
        longest_protocol = self.protocol_matcher.search(f3)[0]
        longest_port = self.port_matcher.search(f4)[0]
        cross = longest_src[1], longest_dest[1], longest_protocol, longest_port
        if cross in self.cross_product:
            return self.cross_product[cross]
        else:
            self.update_cross_product_table(longest_src, longest_dest, longest_protocol, longest_port)
            return self.cross_product[cross]

    def find_earliest_match(self, src_ip, dest_ip, protocol, port):
        best_match = None
        src = src_ip.split('/')[0]
        dest = dest_ip.split('/')[0]
        for rule in self.rules:
            if (ip_addr_in(src, rule.src_ip) and ip_addr_in(dest, rule.dest_ip)
                    and (protocol == rule.protocol or rule.protocol == '*') and (port == rule.port or rule.port == '*')):
                return rule.rule_name, rule.action
        return best_match

    def update_cross_product_table(self, src_ip, dest_ip, protocol, port):
        self.cross_product[(src_ip, dest_ip, protocol, port)] = self.find_earliest_match(src_ip, dest_ip, protocol, port)


def ip_addr_in(ip, prefix):
    parts = prefix.split('/')
    network, mask = parts[0], int(parts[1])
    ip_parts = ip.split('.')
    ip_int = sum(int(octet) << (24 - 8 * i) for i, octet in enumerate(ip_parts))
    prefix_int = network_to_int(network, mask)
    return ip_int >> (32 - mask) == prefix_int


def generate_random_prefixes(num_prefixes):
    res = []

    for i in range(num_prefixes):
        prefix_len = random.randint(0, 32)
        random_ip = random.randint(0, 2 ** 32)
        random_ip = random_ip >> (32 - prefix_len)
        random_ip = random_ip << (32 - prefix_len)

        res.append(int_to_network(random_ip, prefix_len))
    return res


def generate_random_ips(num_ips):
    res = []
    for i in range(num_ips):
        rand_ip = random.randint(0, 2 ** 32)
        ip = int_to_network(rand_ip, 32).split('/')[0]
        res.append(ip)
    return res


def test_trie(num_prefixes, num_lookups, num_removals=10):
    print("############## Testing Trie ##############\n")
    trie = IpPrefixTrie()
    prefixes = generate_random_prefixes(num_prefixes)
    searches = generate_random_ips(num_lookups)
    # with open('bluecat.json') as f:
    #     data = json.load(f)
    #     for prefix in data:
    #         bluecat_prefixes.append((prefix['CidrBlock'], prefix['location']))
    #         searches.append(prefix['CidrBlock'].split('/')[0])
    # searches = searches * 100
    # print(len(bluecat_prefixes))
    # print(len(searches))

    start = perf_counter()
    for i, prefix in enumerate(prefixes):
        trie.insert(prefix, f'route{i}')
    end = perf_counter()
    print(f"Insert took {end - start} seconds")
    # print(f'Size of trie: {pympler.asizeof.asizeof(trie.root)} bytes')
    start = perf_counter()
    for prefix in searches:
        trie.search(prefix)
    end = perf_counter()
    print(f"Search took {end - start} seconds")

    start = perf_counter()
    for i in range(len(prefixes)):
        if i > num_removals:
            break
        trie.remove(prefixes[i], f'route{i}')
    end = perf_counter()
    print(f"Removal took {end - start} seconds")
    return end - start


if __name__ == "__main__":

    test_trie(1_000, 100_000, 100)

    # search1 = test_naive(1_000_000, 1000)
    # search2 = test_trie(1_000_000, 10_000_000)
    # print(f"prefix trie is {search1 / search2} times faster than the original prefix search")

    # test = NaiveIpPrefix()
    # test.insert('10.1.1.0/24', 'route1')
    # print(test.search('10.1.1.0'))
    # print(ip_addr_in('10.1.1.0', '10.1.1.0/24'))
    # rule_set = [Rule('10.1.1.0/24', '8.8.8.8/32', 'tcp', '80', 'rule1'),
    #             Rule('10.1.1.128/25', '10.0.0.0/8', 'udp', '*', 'rule2'),
    #             Rule('0.0.0.0/0', '0.0.0.0/0', '*', '*', 'Drop all'),]
    # rule_set = []
    # counter = 0
    # for item in generate_random_prefixes(500):
    #     for item2 in generate_random_prefixes(1):
    #         rule_set.append(Rule(item, item2, random.choice(['udp', 'tcp']),
    #                              str(random.randint(0, 50)), f'rule{counter}'))
    #         counter += 1
    #
    # print(len(rule_set))
    # field1_matcher = IpPrefixTrie()
    # field2_matcher = IpPrefixTrie()
    # field3_matcher = ProtocolMatcher()
    # field4_matcher = PortMatcher()
    # for rule in rule_set:
    #     field1_matcher.insert(rule.field1, rule.rule_name)
    #     field2_matcher.insert(rule.field2, rule.rule_name)
    #     field3_matcher.insert(rule.field3, rule.rule_name)
    #     field4_matcher.insert(rule.field4, rule.rule_name)
    #
    # cross_product = generate_cross_product_table(rule_set)
    # test = '10.1.1.129', '10.1.234.1', 'udp', '80'
    # longest_f1 = field1_matcher.search(test[0])
    # longest_f2 = field2_matcher.search(test[1])
    # longest_f3 = field3_matcher.search(test[2])[0]
    # longest_f4 = field4_matcher.search(test[3])[0]
    # print(longest_f1, longest_f2, longest_f3, longest_f4)
    # print(cross_product.get((longest_f1[1], longest_f2[1], longest_f3, longest_f4)))





