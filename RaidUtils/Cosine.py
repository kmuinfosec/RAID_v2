import numpy as np
from numpy import dot
from numpy.linalg import norm

def getCosinePairwise(x_data):
    A = np.array(x_data)
    similarity = np.dot(A, A.T)
    square_mag = np.diag(similarity)
    inv_square_mag = 1 / square_mag
    inv_square_mag[np.isinf(inv_square_mag)] = 0
    inv_mag = np.sqrt(inv_square_mag)
    cosine = similarity * inv_mag
    cosine = cosine.T * inv_mag
    return cosine

def getCosineSimilarity(vec1, vec2):
    return dot(vec1, vec2) / (norm(vec1)*norm(vec2))

def getAverageVector(vectors):
    return sum(vectors) / len(vectors)

def getProxyDistance(vectors):
    return 1 - getCosinePairwise(vectors)