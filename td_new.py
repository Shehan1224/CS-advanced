import numpy as np
import pandas as pd
from colorama import Fore, Back, Style, init
from termcolor import colored
import pyfiglet
import requests
import json
import time
from scipy.signal import argrelextrema
from sklearn.ensemble import RandomForestClassifier
from textblob import TextBlob
import nltk
from nltk.sentiment.vader import SentimentIntensityAnalyzer

# Download NLTK data and initialize sentiment analyzer
nltk.download('vader_lexicon')
sia = SentimentIntensityAnalyzer()

# Initialize colorama
init(autoreset=True)

# Initialize AI model
class AIConfirmation:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100)
        self.trained = False
    
    def train_model(self, X, y):
        self.model.fit(X, y)
        self.trained = True
    
    def predict_signal(self, features):
        if not self.trained:
            return 0.5  # Neutral if not trained
        proba = self.model.predict_proba([features])[0]
        return proba[1]  # Probability of positive signal

ai_model = AIConfirmation()

# Banner
def display_banner():
    banner = pyfiglet.figlet_format("CRYPTO SIGNAL BOT PRO", font="slant")
    print(colored(banner, 'cyan'))
    print(colored("="*80, 'blue'))
    print(colored("Enhanced Trading Bot with AI Confirmation & News Analysis", 'yellow'))
    print(colored("                    CREATED BY SHEHAN CHAMIKA", 'cyan'))
    print(colored("="*80, 'blue'))
    print("\n")

# Fetch market data
def get_crypto_data(symbol, interval='1h', limit=500):
    url = f"https://api.binance.com/api/v3/klines?symbol={symbol}&interval={interval}&limit={limit}"
    response = requests.get(url)
    data = json.loads(response.text)
    df = pd.DataFrame(data)
    df = df.iloc[:, :6]
    df.columns = ['time', 'open', 'high', 'low', 'close', 'volume']
    df = df.astype(float)
    df['time'] = pd.to_datetime(df['time'], unit='ms')
    df.set_index('time', inplace=True)
    return df

# Technical Indicators
def calculate_rsi(data, window=14):
    delta = data['close'].diff()
    gain = (delta.where(delta > 0, 0)).rolling(window=window).mean()
    loss = (-delta.where(delta < 0, 0)).rolling(window=window).mean()
    rs = gain / loss
    return 100 - (100 / (1 + rs))

def calculate_macd(data, fast=12, slow=26, signal=9):
    ema_fast = data['close'].ewm(span=fast, adjust=False).mean()
    ema_slow = data['close'].ewm(span=slow, adjust=False).mean()
    macd = ema_fast - ema_slow
    macd_signal = macd.ewm(span=signal, adjust=False).mean()
    macd_hist = macd - macd_signal
    return macd, macd_signal, macd_hist

def calculate_bollinger_bands(data, window=20, num_std=2):
    sma = data['close'].rolling(window=window).mean()
    rolling_std = data['close'].rolling(window=window).std()
    upper_band = sma + (rolling_std * num_std)
    lower_band = sma - (rolling_std * num_std)
    return upper_band, sma, lower_band

def calculate_stochastic_oscillator(data, k_window=14, d_window=3):
    low_min = data['low'].rolling(window=k_window).min()
    high_max = data['high'].rolling(window=k_window).max()
    k = 100 * ((data['close'] - low_min) / (high_max - low_min))
    d = k.rolling(window=d_window).mean()
    return k, d

def calculate_sma(data, window):
    return data['close'].rolling(window=window).mean()

def calculate_atr(data, window=14):
    high_low = data['high'] - data['low']
    high_close = np.abs(data['high'] - data['close'].shift())
    low_close = np.abs(data['low'] - data['close'].shift())
    tr = pd.concat([high_low, high_close, low_close], axis=1).max(axis=1)
    return tr.rolling(window=window).mean()

# SMC Analysis Functions
def calculate_volume_profile(df, bins=20):
    price_range = df['high'].max() - df['low'].min()
    bin_size = price_range / bins
    volume_profile = []
    for i in range(bins):
        lower = df['low'].min() + i * bin_size
        upper = lower + bin_size
        mask = (df['close'] >= lower) & (df['close'] <= upper)
        vol = df.loc[mask, 'volume'].sum()
        volume_profile.append({'lower': lower, 'upper': upper, 'volume': vol})
    return pd.DataFrame(volume_profile)

def detect_order_blocks(df, lookback=20):
    df = df.copy()
    df['ob'] = 0
    
    for i in range(lookback, len(df)):
        if df['close'].iloc[i] > df['open'].iloc[i]:  # Bullish candle
            prev_low = df['low'].iloc[i-lookback:i].min()
            if df['low'].iloc[i] <= prev_low and df['volume'].iloc[i] > df['volume'].iloc[i-1:i+1].mean():
                df.loc[df.index[i], 'ob'] = 1
        
        if df['close'].iloc[i] < df['open'].iloc[i]:  # Bearish candle
            prev_high = df['high'].iloc[i-lookback:i].max()
            if df['high'].iloc[i] >= prev_high and df['volume'].iloc[i] > df['volume'].iloc[i-1:i+1].mean():
                df.loc[df.index[i], 'ob'] = -1
    
    return df

def detect_fvg(df):
    df = df.copy()
    df['fvg'] = 0
    
    for i in range(2, len(df)):
        if df['low'].iloc[i] > df['high'].iloc[i-2]:
            df.loc[df.index[i-1], 'fvg'] = 1
        if df['high'].iloc[i] < df['low'].iloc[i-2]:
            df.loc[df.index[i-1], 'fvg'] = -1
    
    return df

def identify_liquidity_zones(df):
    volume_profile = calculate_volume_profile(df)
    high_volume_nodes = volume_profile.nlargest(3, 'volume')
    swing_highs = df[df['high'] == df['high'].rolling(5, center=True).max()]['high']
    swing_lows = df[df['low'] == df['low'].rolling(5, center=True).min()]['low']
    return {
        'support': swing_lows.tolist() + high_volume_nodes['lower'].tolist(),
        'resistance': swing_highs.tolist() + high_volume_nodes['upper'].tolist()
    }

# Enhanced Analysis Functions
def enhanced_detect_elliott_waves(df, order=5):
    df = df.copy()
    df['wave'] = 0.0
    
    # Find local maxima and minima with stricter criteria
    high_idx = argrelextrema(df['high'].values, np.greater, order=order)[0]
    low_idx = argrelextrema(df['low'].values, np.less, order=order)[0]
    
    # Validate wave structure (5 waves up, 3 waves down pattern)
    waves = []
    for idx in high_idx:
        if len(waves) < 2 or (waves[-1]['type'] == 'low' and df['high'].iloc[idx] > waves[-2]['value']):
            waves.append({'index': idx, 'type': 'high', 'value': df['high'].iloc[idx]})
    
    for idx in low_idx:
        if len(waves) >= 1 and waves[-1]['type'] == 'high' and df['low'].iloc[idx] < waves[-1]['value']:
            waves.append({'index': idx, 'type': 'low', 'value': df['low'].iloc[idx]})
    
    # Label waves according to Elliot Wave theory
    wave_count = 0
    for i in range(len(waves)):
        if waves[i]['type'] == 'high':
            if i % 8 < 5:  # Impulse waves (1,3,5)
                df.loc[df.index[waves[i]['index']], 'wave'] = 1.0 + (i % 2) * 0.5
            else:  # Corrective waves (A,C)
                df.loc[df.index[waves[i]['index']], 'wave'] = 0.8
        else:
            if i % 8 < 5:  # Corrective waves (2,4)
                df.loc[df.index[waves[i]['index']], 'wave'] = -0.6
            else:  # Corrective waves (B)
                df.loc[df.index[waves[i]['index']], 'wave'] = -0.3
    
    return df

def advanced_support_resistance(df, window=20):
    # Calculate pivot points
    df['pivot'] = (df['high'] + df['low'] + df['close']) / 3
    df['s1'] = (2 * df['pivot']) - df['high']
    df['s2'] = df['pivot'] - (df['high'] - df['low'])
    df['r1'] = (2 * df['pivot']) - df['low']
    df['r2'] = df['pivot'] + (df['high'] - df['low'])
    
    # Dynamic support/resistance based on volume and price clustering
    price_bins = pd.cut(df['close'], bins=20)
    # Add observed=True to silence the warning
    volume_by_price = df.groupby(price_bins, observed=True)['volume'].sum().nlargest(5)
    
    supports = []
    resistances = []
    
    for level in volume_by_price.index:
        if level.mid < df['close'].iloc[-1]:
            supports.append(level.mid)
        else:
            resistances.append(level.mid)
    
    # Add traditional support/resistance
    for i in range(2, len(df)-2):
        if df['low'].iloc[i] < df['low'].iloc[i-1] and df['low'].iloc[i] < df['low'].iloc[i+1]:
            supports.append(df['low'].iloc[i])
        if df['high'].iloc[i] > df['high'].iloc[i-1] and df['high'].iloc[i] > df['high'].iloc[i+1]:
            resistances.append(df['high'].iloc[i])
    
    return {
        'supports': sorted(list(set(supports)), reverse=True),
        'resistances': sorted(list(set(resistances)))
    }

def analyze_news_sentiment(news_text):
    sentiment = sia.polarity_scores(news_text)
    blob = TextBlob(news_text)
    blob_sentiment = blob.sentiment.polarity
    
    # Combine both analyses
    combined_score = (sentiment['compound'] + blob_sentiment) / 2
    
    if combined_score > 0.2:
        return "positive"
    elif combined_score < -0.2:
        return "negative"
    else:
        return "neutral"

def assess_entry_safety(df, signal_type):
    recent_candles = df.iloc[-3:]
    
    # Check for strong momentum in signal direction
    if signal_type == "BUY":
        momentum = (recent_candles['close'] > recent_candles['open']).sum() / 3
        volatility = recent_candles['high'].max() - recent_candles['low'].min()
    else:  # SELL
        momentum = (recent_candles['close'] < recent_candles['open']).sum() / 3
        volatility = recent_candles['high'].max() - recent_candles['low'].min()
    
    # Check if price is at key levels
    sr_levels = advanced_support_resistance(df)
    near_key_level = False
    current_price = df['close'].iloc[-1]
    
    if signal_type == "BUY":
        for s in sr_levels['supports']:
            if abs(current_price - s) < current_price * 0.01:
                near_key_level = True
                break
    else:
        for r in sr_levels['resistances']:
            if abs(current_price - r) < current_price * 0.01:
                near_key_level = True
                break
    
    # Calculate safety score (0-1)
    safety_score = (momentum * 0.4) + (min(volatility/current_price, 0.05)/0.05 * 0.3) + (near_key_level * 0.3)
    
    return safety_score

def calculate_indicators(df):
    df = df.copy()
    df['rsi'] = calculate_rsi(df)
    df['macd'], df['macd_signal'], df['macd_hist'] = calculate_macd(df)
    df['upper_band'], df['middle_band'], df['lower_band'] = calculate_bollinger_bands(df)
    df['slowk'], df['slowd'] = calculate_stochastic_oscillator(df)
    df['sma_50'] = calculate_sma(df, 50)
    df['sma_200'] = calculate_sma(df, 200)
    df = detect_order_blocks(df)
    df = detect_fvg(df)
    return df

def calculate_fibonacci_levels(df, lookback=50):
    recent_high = df['high'].rolling(lookback).max().iloc[-1]
    recent_low = df['low'].rolling(lookback).min().iloc[-1]
    diff = recent_high - recent_low
    return {
        '0': recent_high,
        '0.236': recent_high - diff * 0.236,
        '0.382': recent_high - diff * 0.382,
        '0.5': recent_high - diff * 0.5,
        '0.618': recent_high - diff * 0.618,
        '0.786': recent_high - diff * 0.786,
        '1': recent_low
    }

def calculate_tp_sl(df, signal_type):
    atr = calculate_atr(df).iloc[-1]
    current_price = df['close'].iloc[-1]
    if signal_type == "BUY":
        return round(current_price + 3 * atr, 4), round(current_price - 2 * atr, 4)
    else:
        return round(current_price - 3 * atr, 4), round(current_price + 2 * atr, 4)

def generate_signals(df, fib_levels, liquidity_zones):
    current_price = df['close'].iloc[-1]
    
    # RSI Signal
    rsi = df['rsi'].iloc[-1]
    rsi_signal = "BUY" if rsi < 30 else "SELL" if rsi > 70 else None
    rsi_prob = min(100, 80 + (30 - rsi) * 2) if rsi < 30 else min(100, 80 + (rsi - 70) * 2) if rsi > 70 else 0
    
    # MACD Signal
    macd = df['macd'].iloc[-1]
    macd_signal = df['macd_signal'].iloc[-1]
    macd_hist = df['macd_hist'].iloc[-1]
    macd_signal_dir = "BUY" if macd > macd_signal and macd_hist > 0 else "SELL" if macd < macd_signal and macd_hist < 0 else None
    macd_prob = min(100, 70 + abs(macd_hist) * 100) if macd_signal_dir else 0
    
    # Fibonacci Signal
    fib_signal, fib_prob = None, 0
    for level, price in fib_levels.items():
        if abs(current_price - price) < current_price * 0.005:
            fib_signal = "BUY" if float(level) < 0.5 else "SELL"
            fib_prob = 80 - float(level) * 100 if float(level) < 0.5 else float(level) * 100 - 20
    
    # Elliot Wave Signal
    df = enhanced_detect_elliott_waves(df)
    last_wave = df['wave'].iloc[-3:].mean()
    wave_signal = "SELL" if last_wave > 0.5 else "BUY" if last_wave < -0.5 else None
    wave_prob = 75 if wave_signal else 0
    
    # SMC Signals
    recent_ob = df['ob'].iloc[-5:].mean()
    smc_signal = "BUY" if recent_ob > 0.3 else "SELL" if recent_ob < -0.3 else None
    smc_prob = 75 if smc_signal else 0
    
    recent_fvg = df['fvg'].iloc[-3:].mean()
    if recent_fvg > 0.3 and (not smc_signal or smc_signal == "BUY"):
        smc_signal = "BUY"
        smc_prob = max(smc_prob, 65)
    elif recent_fvg < -0.3 and (not smc_signal or smc_signal == "SELL"):
        smc_signal = "SELL"
        smc_prob = max(smc_prob, 65)
    
    # Support/Resistance Analysis
    sr_levels = advanced_support_resistance(df)
    nearest_support = min([s for s in sr_levels['supports'] if s < current_price], default=None)
    nearest_resistance = max([r for r in sr_levels['resistances'] if r > current_price], default=None)
    
    if nearest_support and (current_price - nearest_support) < current_price * 0.01:
        smc_signal = "BUY"
        smc_prob = max(smc_prob, 70)
    elif nearest_resistance and (nearest_resistance - current_price) < current_price * 0.01:
        smc_signal = "SELL"
        smc_prob = max(smc_prob, 70)
    
    # Combine signals
    combined_signals = {
        'RSI': (rsi_signal, rsi_prob),
        'MACD': (macd_signal_dir, macd_prob),
        'Fibonacci': (fib_signal, fib_prob),
        'Elliot Wave': (wave_signal, wave_prob),
        'SMC': (smc_signal, smc_prob)
    }
    
    # AI Confirmation
    ai_features = [
        df['rsi'].iloc[-1],
        df['macd_hist'].iloc[-1],
        df['slowk'].iloc[-1],
        df['slowd'].iloc[-1],
        df['ob'].iloc[-5:].mean(),
        df['fvg'].iloc[-3:].mean()
    ]
    ai_confirmation = ai_model.predict_signal(ai_features)
    
    # News Analysis (placeholder - would need actual news data)
    news_effect = "neutral"
    
    # Add to combined signals
    combined_signals['AI Confirmation'] = (combined_signals.get('SMC', (None, 0))[0], ai_confirmation * 100)
    combined_signals['News Impact'] = (news_effect, 0)
    
    # Calculate final signal
    buy_signals = [sig for sig, prob in combined_signals.values() if sig == "BUY"]
    sell_signals = [sig for sig, prob in combined_signals.values() if sig == "SELL"]
    
    if not buy_signals and not sell_signals:
        return {'signal': "HOLD", 'probability': 0, 'details': combined_signals, 'tp': None, 'sl': None, 'entry_safety': 0}
    
    buy_prob = np.mean([prob for sig, prob in combined_signals.values() if sig == "BUY"] or [0])
    sell_prob = np.mean([prob for sig, prob in combined_signals.values() if sig == "SELL"] or [0])
    
    if buy_prob > sell_prob and buy_prob > 60:
        tp, sl = calculate_tp_sl(df, "BUY")
        entry_safety = assess_entry_safety(df, "BUY")
        return {'signal': "BUY", 'probability': min(95, buy_prob), 'details': combined_signals, 'tp': tp, 'sl': sl, 'entry_safety': entry_safety}
    elif sell_prob > buy_prob and sell_prob > 60:
        tp, sl = calculate_tp_sl(df, "SELL")
        entry_safety = assess_entry_safety(df, "SELL")
        return {'signal': "SELL", 'probability': min(95, sell_prob), 'details': combined_signals, 'tp': tp, 'sl': sl, 'entry_safety': entry_safety}
    else:
        return {'signal': "HOLD", 'probability': 0, 'details': combined_signals, 'tp': None, 'sl': None, 'entry_safety': 0}

def display_results(symbol, signals, fib_levels, current_price, df, liquidity_zones):
    print("\n" + "="*80)
    print(colored(f"CRYPTO SIGNAL ANALYSIS: {symbol}", 'yellow', attrs=['bold']))
    print(colored(f"Current Price: {current_price}", 'white'))
    print("="*80)
    
    print("\n" + colored("SMART MONEY CONCEPT ANALYSIS:", 'magenta'))
    last_ob = df['ob'].iloc[-5:]
    print(f"Recent Order Blocks: Bullish {len(last_ob[last_ob > 0])} | Bearish {len(last_ob[last_ob < 0])}")
    last_fvg = df['fvg'].iloc[-3:]
    print(f"Fair Value Gaps: Bullish {len(last_fvg[last_fvg > 0])} | Bearish {len(last_fvg[last_fvg < 0])}")
    
    sr_levels = advanced_support_resistance(df)
    print("\nKey Support/Resistance Levels:")
    print(f"Nearest Support: {min([s for s in sr_levels['supports'] if s < current_price], default='None')}")
    print(f"Nearest Resistance: {max([r for r in sr_levels['resistances'] if r > current_price], default='None')}")
    
    print("\n" + colored("FIBONACCI RETRACEMENT LEVELS:", 'cyan'))
    for level, price in fib_levels.items():
        diff_pct = (current_price - price) / price * 100
        print(f"{level.ljust(6)}: {price:.4f} ({diff_pct:+.2f}%)")
    
    print("\n" + colored("INDICATOR ANALYSIS:", 'cyan'))
    for indicator, (signal, prob) in signals['details'].items():
        if signal:
            if isinstance(signal, str):
                color = Fore.GREEN if signal == "BUY" else Fore.RED if signal == "SELL" else Fore.YELLOW
                print(f"{indicator.ljust(15)}: {color}{signal} (Probability: {prob:.1f}%){Style.RESET_ALL}")
            else:
                print(f"{indicator.ljust(15)}: {signal} (Probability: {prob:.1f}%)")
        else:
            print(f"{indicator.ljust(15)}: No clear signal")
    
    print("\n" + colored("COMBINED SIGNAL:", 'magenta', attrs=['bold']))
    if signals['signal'] != "HOLD":
        color = Fore.GREEN if signals['signal'] == "BUY" else Fore.RED
        print(f"STRONG {color}{signals['signal']} SIGNAL DETECTED{Style.RESET_ALL}")
        print(f"Confidence Level: {color}{signals['probability']:.1f}%{Style.RESET_ALL}")
        print(f"Entry Safety: {'High' if signals['entry_safety'] > 0.7 else 'Medium' if signals['entry_safety'] > 0.5 else 'Low'}")
        print(f"Take Profit: {Fore.GREEN}{signals['tp']}{Style.RESET_ALL}")
        print(f"Stop Loss: {Fore.RED}{signals['sl']}{Style.RESET_ALL}")
    else:
        print("No strong trading signal detected")
    
    print("\n" + colored("RECOMMENDATION:", 'yellow', attrs=['bold']))
    if signals['signal'] != "HOLD" and signals['probability'] >= 80 and signals['entry_safety'] > 0.7:
        color = Fore.GREEN if signals['signal'] == "BUY" else Fore.RED
        print(color + f"STRONG {signals['signal']} RECOMMENDATION (High Confidence & Safety)" + Style.RESET_ALL)
    elif signals['signal'] != "HOLD" and signals['probability'] >= 65:
        color = Fore.GREEN if signals['signal'] == "BUY" else Fore.RED
        print(color + f"Consider {signals['signal']} position (Moderate Confidence)" + Style.RESET_ALL)
    else:
        print("No clear trading opportunity - Wait for better setup")
    
    print("="*80 + "\n")

def analyze_multiple_coins(coins, interval='1h'):
    results = {}
    for coin in coins:
        try:
            print(colored(f"\nAnalyzing {coin}...", 'blue'))
            df = get_crypto_data(coin, interval)
            df = calculate_indicators(df)
            liquidity_zones = identify_liquidity_zones(df)
            fib_levels = calculate_fibonacci_levels(df)
            signals = generate_signals(df, fib_levels, liquidity_zones)
            
            if signals['signal'] != "HOLD" and signals['probability'] >= 75:
                results[coin] = {
                    'signal': signals['signal'],
                    'probability': signals['probability'],
                    'price': df['close'].iloc[-1],
                    'tp': signals['tp'],
                    'sl': signals['sl'],
                    'safety': signals['entry_safety']
                }
                display_results(coin, signals, fib_levels, df['close'].iloc[-1], df, liquidity_zones)
            else:
                print(colored(f"No strong signal for {coin}", 'yellow'))
        except Exception as e:
            print(colored(f"Error analyzing {coin}: {str(e)}", 'red'))
    return results

def main():
    display_banner()
    analysis_type = input("Single coin or multi-coin analysis? (s/m): ").lower()
    
    if analysis_type == 's':
        symbol = input("Enter crypto pair (e.g., BTCUSDT): ").upper()
        interval = input("Enter time interval (e.g., 1h, 4h, 1d): ")
        
        print("\n" + colored("Fetching market data...", 'blue'))
        df = get_crypto_data(symbol, interval)
        
        print(colored("Calculating technical indicators...", 'blue'))
        df = calculate_indicators(df)
        
        print(colored("Detecting SMC patterns...", 'blue'))
        liquidity_zones = identify_liquidity_zones(df)
        
        print(colored("Analyzing Fibonacci levels...", 'blue'))
        fib_levels = calculate_fibonacci_levels(df)
        
        print(colored("Generating trading signals...", 'blue'))
        signals = generate_signals(df, fib_levels, liquidity_zones)
        
        display_results(symbol, signals, fib_levels, df['close'].iloc[-1], df, liquidity_zones)
        
    elif analysis_type == 'm':
        coins_input = input("Enter crypto pairs separated by commas (e.g., BTCUSDT,ETHUSDT,SOLUSDT): ")
        coins = [coin.strip().upper() for coin in coins_input.split(',')]
        interval = input("Enter time interval (e.g., 1h, 4h, 1d): ")
        
        print("\n" + colored("Starting multi-coin analysis...", 'blue'))
        results = analyze_multiple_coins(coins, interval)
        
        print("\n" + colored("SUMMARY OF STRONG SIGNALS:", 'green', attrs=['bold']))
        if results:
            for coin, data in results.items():
                color = Fore.GREEN if data['signal'] == "BUY" else Fore.RED
                print(f"{coin}: {color}{data['signal']} (Confidence: {data['probability']:.1f}%, Safety: {'High' if data['safety'] > 0.7 else 'Medium' if data['safety'] > 0.5 else 'Low'})")
                print(f"   Price: {data['price']} | TP: {data['tp']} | SL: {data['sl']}")
        else:
            print("No strong signals found across all analyzed coins")
    
    print(colored("\nAnalysis complete. Press Ctrl+C to exit.", 'green'))
    try:
        time.sleep(6000)
    except KeyboardInterrupt:
        print("\n" + colored("Exiting Crypto Signal Bot...", 'red'))
    
    if analysis_type == 's':
        while True:
            time.sleep(300)
            print("\n" + colored("Updating data...", 'blue'))
            df = get_crypto_data(symbol, interval)
            df = calculate_indicators(df)
            liquidity_zones = identify_liquidity_zones(df)
            fib_levels = calculate_fibonacci_levels(df)
            signals = generate_signals(df, fib_levels, liquidity_zones)
            display_results(symbol, signals, fib_levels, df['close'].iloc[-1], df, liquidity_zones)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + colored("Exiting Crypto Signal Bot...", 'red'))
    except Exception as e:
        print("\n" + colored(f"Error: {str(e)}", 'red'))
