"""Variational autoencoder for clean-only anomaly scoring (study guide, section 5, step 4).

Architecture  input -> 64 -> 32 -> (mean, log-variance), 8-d -> 32 -> 64 -> input (ReLU; linear output)
Likelihood    Gaussian decoder with unit variance on standardised features, so
              -log p(x|z) = 0.5 * sum_j (x_j - x_hat_j)^2 + const (summed over features, not averaged)
Training      ELBO on the clean training rows only; 50 epochs, batch 32 (the paper autoencoder's settings);
              KL weight ramped 0 -> 1 over the first 10 epochs to avoid posterior collapse; log-variance
              clipped and gradients norm-clipped because some standardised features are extreme
Score         negative ELBO with z = mean (deterministic, so conformal p-values and SHAP are reproducible):
              0.5 * ||x - decoder(mean)||^2 + KL(q(z|x) || N(0, I)); higher = less like clean data
"""
import numpy as np

LATENT = 8


def build(input_dim):
    import tensorflow as tf

    L = tf.keras.layers
    x = L.Input(shape=(input_dim,))
    h = L.Dense(32, activation='relu')(L.Dense(64, activation='relu')(x))
    encoder = tf.keras.Model(x, [L.Dense(LATENT)(h), L.Dense(LATENT)(h)])
    z = L.Input(shape=(LATENT,))
    h = L.Dense(64, activation='relu')(L.Dense(32, activation='relu')(z))
    decoder = tf.keras.Model(z, L.Dense(input_dim)(h))
    return encoder, decoder


def terms(model, x, sample):
    """Per-row reconstruction and KL terms of the negative ELBO."""
    import tensorflow as tf

    encoder, decoder = model
    mu, logvar = encoder(x)
    logvar = tf.clip_by_value(logvar, -10.0, 10.0)
    z = mu + tf.exp(0.5 * logvar) * tf.random.normal(tf.shape(mu)) if sample else mu
    recon = 0.5 * tf.reduce_sum(tf.square(x - decoder(z)), axis=1)
    kl = 0.5 * tf.reduce_sum(tf.exp(logvar) + tf.square(mu) - 1.0 - logvar, axis=1)
    return recon, kl


def fit_vae(X_train, seed, epochs=50, batch_size=32, warmup=10, verbose=0):
    """Returns (model, history); history holds the mean reconstruction and KL terms of each epoch's last batch."""
    import tensorflow as tf

    tf.random.set_seed(seed)
    model = build(X_train.shape[1])
    weights = model[0].trainable_weights + model[1].trainable_weights
    opt = tf.keras.optimizers.Adam(1e-3, clipnorm=5.0)

    @tf.function
    def step(x, beta):
        with tf.GradientTape() as tape:
            recon, kl = terms(model, x, sample=True)
            loss = tf.reduce_mean(recon + beta * kl)
        opt.apply_gradients(zip(tape.gradient(loss, weights), weights))
        return tf.reduce_mean(recon), tf.reduce_mean(kl)

    rng = np.random.default_rng(seed)
    history = []
    for epoch in range(epochs):
        beta = tf.constant(min(1.0, (epoch + 1) / warmup), tf.float32)
        idx = rng.permutation(len(X_train))
        for i in range(0, len(idx), batch_size):
            recon, kl = step(X_train[idx[i:i + batch_size]], beta)
        history.append((float(recon), float(kl)))
        if verbose:
            print(f'  epoch {epoch + 1}: recon {history[-1][0]:.3f}  KL {history[-1][1]:.3f}', flush=True)
    return model, history


def score_terms(model, X, batch=4096):
    """Deterministic (z = mean) reconstruction and KL terms for every row."""
    import tensorflow as tf

    out = [terms(model, tf.constant(X[i:i + batch]), sample=False) for i in range(0, len(X), batch)]
    return np.concatenate([r.numpy() for r, _ in out]), np.concatenate([k.numpy() for _, k in out])


def neg_elbo(model, X):
    recon, kl = score_terms(model, X)
    return recon.astype(np.float64) + kl
