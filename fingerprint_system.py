import numpy as np
from scipy.spatial import cKDTree
from scipy.optimize import minimize
from phe import paillier
import matplotlib.pyplot as plt
import io

class FingerprintSystem:
    def __init__(self, key_size=2048):
        """Initialize the fingerprint system with Paillier homomorphic encryption"""
        self.public_key, self.private_key = paillier.generate_paillier_keypair(n_length=key_size)
        self.templates = {}
        self.scores = {'genuine': [], 'imposter': []}

    def read_minutiae(self, file_content):
        """Read minutiae points from file content"""
        try:
            data = np.loadtxt(io.StringIO(file_content), dtype=np.float64, usecols=(0, 1, 2))
        except (ValueError, IndexError):
            try:
                data = np.loadtxt(io.StringIO(file_content), dtype=np.float64)
                if data.shape[1] < 3:
                    raise ValueError("Minutiae file must have at least 3 columns (x, y, angle)")
            except Exception as e:
                raise ValueError(f"Error reading minutiae file: {str(e)}")

        if data.ndim == 1:
            if len(data) >= 3:
                data = data[:3]
                data = data.reshape(1, -1)
            else:
                raise ValueError("Each minutiae point must have at least x,y,angle")

        return data

    def encrypt_template(self, minutiae):
        """Encrypt minutiae template using Paillier homomorphic encryption"""
        encrypted = []
        for point in minutiae:
            encrypted_point = [
                self.public_key.encrypt(float(point[0])),
                self.public_key.encrypt(float(point[1])),
                self.public_key.encrypt(float(point[2]))
            ]
            encrypted.append(encrypted_point)
        return np.array(encrypted)

    def decrypt_template(self, encrypted_template):
        """Decrypt an encrypted minutiae template"""
        decrypted = []
        for point in encrypted_template:
            decrypted_point = [
                self.private_key.decrypt(point[0]),
                self.private_key.decrypt(point[1]),
                self.private_key.decrypt(point[2])
            ]
            decrypted.append(decrypted_point)
        return np.array(decrypted)

    def print_encrypted_template(self, encrypted_template, name="Template", limit=3):
        """Print the encrypted values in a human-readable format"""
        print(f"\n{name} Encryption Details:")
        print(f"Public Key (n): {self.public_key.n}")
        print(f"Number of minutiae points: {len(encrypted_template)}")
        print("\nFirst few encrypted points (x, y, angle):")

        for i, point in enumerate(encrypted_template[:limit]):
            print(f"\nPoint {i+1}:")
            print(f"  x: {point[0].ciphertext()} (hex: {hex(point[0].ciphertext())[:20]}...)")
            print(f"  y: {point[1].ciphertext()} (hex: {hex(point[1].ciphertext())[:20]}...)")
            print(f"  angle: {point[2].ciphertext()} (hex: {hex(point[2].ciphertext())[:20]}...)")

    def preprocess(self, minutiae):
        """Normalize minutiae points for comparison"""
        if len(minutiae) < 1:
            return minutiae

        processed = minutiae.copy()

        centroid = np.mean(processed[:, :2], axis=0)
        processed[:, :2] -= centroid

        std_dev = np.std(processed[:, :2])
        if std_dev > 1e-6:
            processed[:, :2] /= std_dev

        processed[:, 2] = (processed[:, 2] % 360) / 360

        return processed

    def align_templates(self, source, target):
        """Find optimal alignment between two minutiae sets"""
        if len(source) < 2 or len(target) < 2:
            return 0.0, 1.0

        def alignment_error(params):
            angle, tx, ty, scale = params
            rot_mat = np.array([
                [np.cos(angle), -np.sin(angle)],
                [np.sin(angle), np.cos(angle)]
            ])
            transformed = scale * np.dot(source[:, :2], rot_mat) + np.array([tx, ty])
            tree = cKDTree(target[:, :2])
            distances, _ = tree.query(transformed, k=1)
            return np.mean(distances)

        initial_params = [0.0, 0.0, 0.0, 1.0]

        bounds = [
            (-np.pi, np.pi),
            (-2.0, 2.0),
            (-2.0, 2.0),
            (0.5, 1.5)
        ]

        result = minimize(
            alignment_error,
            initial_params,
            bounds=bounds,
            method='L-BFGS-B',
            options={'maxiter': 100}
        )

        return result.x[0], result.x[3]

    def secure_match(self, encrypted_query, template_id, dist_thresh=0.5, angle_thresh=0.1):
        """Perform secure matching between encrypted query and stored template"""
        stored_encrypted = self.templates.get(template_id)
        if stored_encrypted is None:
            return 0.0

        query = self.decrypt_template(encrypted_query)
        target = self.decrypt_template(stored_encrypted)

        query_proc = self.preprocess(query)
        target_proc = self.preprocess(target)

        angle, scale = self.align_templates(query_proc, target_proc)

        rot_mat = np.array([
            [np.cos(angle), -np.sin(angle)],
            [np.sin(angle), np.cos(angle)]
        ])

        transformed = scale * np.dot(query_proc[:, :2], rot_mat)

        tree = cKDTree(target_proc[:, :2])

        dists, indices = tree.query(transformed)

        matches = 0
        for i, (dist, idx) in enumerate(zip(dists, indices)):
            if dist < dist_thresh:
                angle_diff = abs((query_proc[i, 2] + angle/(2*np.pi)) % 1.0 - target_proc[idx, 2])
                angle_diff = min(angle_diff, 1 - angle_diff)
                if angle_diff < angle_thresh:
                    matches += 1

        return matches / min(len(query_proc), len(target_proc))

    def evaluate_system(self):
        """Evaluate system performance using FAR/FRR metrics"""
        genuine_scores = np.array(self.scores['genuine'])
        imposter_scores = np.array(self.scores['imposter']) if self.scores['imposter'] else np.array([])

        metrics = {
            'FAR': [],
            'FRR': [],
            'EER': np.nan,
            'EER_Threshold': np.nan,
            'Genuine_Mean': np.mean(genuine_scores) if len(genuine_scores) > 0 else np.nan,
            'Imposter_Mean': np.mean(imposter_scores) if len(imposter_scores) > 0 else np.nan
        }

        if len(imposter_scores) > 0:
            thresholds = np.linspace(0, 1, 100)
            far = []
            frr = []

            for th in thresholds:
                far.append(np.mean(imposter_scores >= th))
                frr.append(np.mean(genuine_scores < th))

            metrics['FAR'] = far
            metrics['FRR'] = frr

            diff = np.abs(np.array(far) - np.array(frr))
            eer_index = np.argmin(diff)
            metrics['EER'] = (far[eer_index] + frr[eer_index]) / 2
            metrics['EER_Threshold'] = thresholds[eer_index]

            plt.figure(figsize=(10, 6))
            plt.plot(thresholds, far, label='FAR (False Accept Rate)')
            plt.plot(thresholds, frr, label='FRR (False Reject Rate)')
            plt.axvline(x=metrics['EER_Threshold'], color='r', linestyle='--',
                       label=f'EER at {metrics["EER_Threshold"]:.2f}')
            plt.xlabel('Matching Threshold')
            plt.ylabel('Rate')
            plt.title('System Performance (FAR vs FRR)')
            plt.legend()
            plt.grid(True)
            plt.show()

        return metrics

def main():
    print("Fingerprint Recognition System with Homomorphic Encryption")
    print("-----------------------------------------------------")
    # This main driver expects user interaction, typical of local terminal usage.

if __name__ == "__main__":
    main()
