import hashlib
import itertools
import time
import string

class Hashing:
    def __init__(self, data):
        self.hash_types = [
            "sha256",
            "sha512",
            "md5",
            "sha1",
            "sha224",
            "sha384"
        ]
        self.data = data

    def get_hash_types(self):
        return self.hash_types

    def hashing_file(self, file_path, type="sha256"):
        with open(file_path, "rb") as f:
            data = f.read()
            return self.hash(data, type)
    
    def hash(self, data, type="sha256"):
        if type=="asha256":
            return hashlib.sha256(data.encode()).hexdigest()
        elif type=="sha512":
            return hashlib.sha512(data.encode()).hexdigest()
        elif type=="md5":
            return hashlib.md5(data.encode()).hexdigest()
        elif type=="sha1":
            return hashlib.sha1(data.encode()).hexdigest()
        elif type=="sha224":
            return hashlib.sha224(data.encode()).hexdigest()
        elif type=="sha384":
            return hashlib.sha384(data.encode()).hexdigest()
        else:
            return "Invalid hash type"
    
    def verify(self, hash, data, type="sha256"):
        return self.hash(data, type) == hash

    def benchmark(self, type="sha256", duration=1.0):
        start = time.time()
        count = 0
        data = "benchmark_data"
        while time.time() - start < duration:
            self.hash(f"{data}{count}", type)
            count += 1
        return count / duration

    def estimate_time(self, length, charset_size, hashrate):
        combinations = charset_size ** length
        seconds = combinations / hashrate
        return seconds

    def crack_bruteforce(self, target_hash, type="sha256", max_length=5, charset=None, callback=None):
        
        if charset is None:
            charset = string.ascii_lowercase + string.digits
            
        for length in range(1, max_length + 1):
            for attempt in itertools.product(charset, repeat=length):
                candidate = "".join(attempt)
                if callback and not callback(candidate):
                    return None # Stop if callback returns False
                    
                if self.hash(candidate, type) == target_hash:
                    return candidate
        return None