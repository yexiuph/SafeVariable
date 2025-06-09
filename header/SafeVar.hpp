#pragma once

#include <iostream>
#include <string>
#include <memory>
#include <Windows.h>
#include <mutex>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <random>
#include <array>
#include <ostream>
#include <algorithm>
#include <numeric>
#include <stdexcept>

/**
 * @file    SafeVar.hpp
 * @brief   Secure variable wrapper and memory safety utilities for obfuscation and anti-cheat.
 *
 * Provides SafeVar<T> for secure variable storage, memory pool management, and
 * custom allocators with obfuscation using ChaCha20 encryption.
 *
 * @author  Christian Louis Abrigo ( YeXiuPH )
 * @date    Feb 16, 2025
 * @copyright
 *   Copyright (c) 2025 YXGames. All rights reserved.
 */


// Utility to load 32-bit little-endian integers
inline uint32_t LoadLE32 ( const uint8_t* src )
{
	return static_cast< uint32_t >( src [ 0 ] ) |
		( static_cast< uint32_t >( src [ 1 ] ) << 8 ) |
		( static_cast< uint32_t >( src [ 2 ] ) << 16 ) |
		( static_cast< uint32_t >( src [ 3 ] ) << 24 );

}

// Secure nonce generator
void GenerateNonce ( std::array<uint8_t, 12>& nonceOut )
{
	std::random_device rd;
	std::generate ( nonceOut.begin ( ), nonceOut.end ( ), std::ref ( rd ) );
}

// FNV-1a checksum
uint32_t ComputeChecksumFNV ( const uint8_t* data, size_t len )
{
	const uint32_t fnv_prime = 0x01000193;
	uint32_t hash = 0x811C9DC5;
	for ( size_t i = 0; i < len; ++i ) {
		hash ^= data [ i ];
		hash *= fnv_prime;

	}
	return hash;
}

class ChaCha20
{
public:
	// Constants for ChaCha20
	static constexpr uint32_t constants [ 4 ] = { 0x61707865, 0x3320646e, 0x79622d36, 0x6b206574 };

	// ChaCha20 block function
	static void Block ( std::array<uint32_t, 16>& state, uint8_t* output )
	{
		std::array<uint32_t, 16> workingState = state;
		for ( int i = 0; i < 20; i += 2 ) {
			// Odd rounds
			QuarterRound ( workingState, 0, 4, 8, 12 );
			QuarterRound ( workingState, 1, 5, 9, 13 );
			QuarterRound ( workingState, 2, 6, 10, 14 );
			QuarterRound ( workingState, 3, 7, 11, 15 );

			// Even rounds
			QuarterRound ( workingState, 0, 5, 10, 15 );
			QuarterRound ( workingState, 1, 6, 11, 12 );
			QuarterRound ( workingState, 2, 7, 8, 13 );
			QuarterRound ( workingState, 3, 4, 9, 14 );
		}

		// Add the original state values to the working state (after the rounds)
		for ( int i = 0; i < 16; ++i ) {
			workingState [ i ] += state [ i ];
		}

		// Store the result in the output buffer
		std::memcpy ( output, workingState.data ( ), 64 );  // 64 bytes per block
	}

	// QuarterRound function (used in the state mixing)
	static void QuarterRound ( std::array<uint32_t, 16>& state, int a, int b, int c, int d )
	{
		state [ a ] += state [ b ]; state [ d ] ^= state [ a ]; state [ d ] = RotateLeft ( state [ d ], 16 );
		state [ c ] += state [ d ]; state [ b ] ^= state [ c ]; state [ b ] = RotateLeft ( state [ b ], 12 );
		state [ a ] += state [ b ]; state [ d ] ^= state [ a ]; state [ d ] = RotateLeft ( state [ d ], 8 );
		state [ c ] += state [ d ]; state [ b ] ^= state [ c ]; state [ b ] = RotateLeft ( state [ b ], 7 );
	}

	// Rotate left function (used in QuarterRound)
	static uint32_t RotateLeft ( uint32_t x, uint32_t n )
	{
		return ( x << n ) | ( x >> ( 32 - n ) );
	}

	// Encrypt/decrypt a block of data with ChaCha20
	static void Encrypt ( const uint8_t* input, uint8_t* output, size_t length, const uint8_t* key, const uint8_t* nonce )
	{
		// Prepare the initial state
		std::array<uint32_t, 16> state;

		// Load ChaCha20 constants
		for ( int i = 0; i < 4; ++i ) {
			state [ i ] = constants [ i ];
		}

		// Load 256-bit key (8 words)
		for ( int i = 0; i < 8; ++i ) {
			state [ 4 + i ] = LoadLE32 ( key + i * 4 );
		}

		// Initialize counter to 0
		uint32_t counter = 0; // Ensure counter starts at 0
		state [ 12 ] = counter;
		state [ 13 ] = 0;

		// Load 64-bit nonce into two 32-bit words
		state [ 14 ] = LoadLE32 ( nonce + 0 );
		state [ 15 ] = LoadLE32 ( nonce + 4 );

		size_t bytesProcessed = 0;

		while ( bytesProcessed < length ) {
			// Set the counter value
			state [ 12 ] = counter++;

			// Generate a block of keystream
			uint8_t keystream [ 64 ];
			Block ( state, keystream );

			// XOR input with keystream to produce output
			size_t blockSize = ( length - bytesProcessed ) < 64 ? ( length - bytesProcessed ) : 64;
			for ( size_t i = 0; i < blockSize; ++i ) {
				output [ bytesProcessed + i ] = input [ bytesProcessed + i ] ^ keystream [ i ];
			}

			bytesProcessed += blockSize;
		}

		// !TODO : Add HMAC Processing
		// Note: Add OpenSSL or Crypto++ for much more secure stuff.
	}
};

/**
 * @brief RealMemoryAllocator and FakeMemoryAllocator for manipulating memory safely.
 *
 * RealMemoryAllocator uses VirtualAlloc to allocate real memory. FakeMemoryAllocator uses
 * a simulated address space to fool cheaters.
 */

 // Real Memory Allocator using Windows API
class RealMemoryAllocator
{
public:
	// Allocate real memory using VirtualAlloc
	static void* AllocateRealMemory ( size_t size )
	{
		void* ptr = VirtualAlloc ( NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
		if ( !ptr ) {
			throw std::runtime_error ( "Memory allocation failed" );
		}
		return ptr;
	}

	// Free allocated memory using VirtualFree
	static void FreeRealMemory ( void* ptr )
	{
		if ( !VirtualFree ( ptr, 0, MEM_RELEASE ) ) {
			throw std::runtime_error ( "Memory free failed" );
		}
	}
};


// Fake Memory Allocator that simulates memory addresses
class FakeMemoryAllocator
{
private:
	static uintptr_t fakeBaseAddress;
	static std::mutex mtx;

public:
	// Allocate fake memory (simulated addresses)
	static uintptr_t AllocateFakeMemory ( size_t size )
	{
		std::lock_guard<std::mutex> lock ( mtx );
		uintptr_t allocatedAddress = fakeBaseAddress;
		fakeBaseAddress += size + 0x10;  // Increment to simulate allocation
		return allocatedAddress;
	}

	static void ResetAllocator ( )
	{
		fakeBaseAddress = 0x10000000;  // Reset fake memory space to initial state
	}
};

uintptr_t FakeMemoryAllocator::fakeBaseAddress = 0x10000000;  // Starting fake memory address
std::mutex FakeMemoryAllocator::mtx;  // Mutex to protect fake memory allocation

class MemoryPool
{
private:
	std::vector<void*> freeBlocks; // Holds free blocks of memory
	std::mutex mtx; // Mutex for thread safety

public:
	void* Allocate ( size_t size )
	{
		std::lock_guard<std::mutex> lock ( mtx );
		if ( !freeBlocks.empty ( ) ) {
			void* ptr = freeBlocks.back ( );
			freeBlocks.pop_back ( );
			return ptr;
		}
		return RealMemoryAllocator::AllocateRealMemory ( size ); // Fall back to system allocator
	}

	void Free ( void* ptr )
	{
		std::lock_guard<std::mutex> lock ( mtx );
		freeBlocks.push_back ( ptr ); // Return to pool for reuse
	}

	~MemoryPool ( )
	{
		for ( auto ptr : freeBlocks ) {
			RealMemoryAllocator::FreeRealMemory ( ptr );
		}
	}
};

// SafeVar class for secure variable handling with obfuscation and memory manipulation
template<typename T>
class SafeVar
{
	static_assert( std::is_trivially_copyable<T>::value&& std::is_default_constructible<T>::value,
		"SafeVar<T> requires trivially copyable and default-constructible types." );

private:
	static MemoryPool memoryPool;
	static constexpr size_t VALUE_SIZE = sizeof ( T );

	alignas( T ) std::array<uint8_t, VALUE_SIZE> buffer;
	alignas( T ) std::array<uint8_t, VALUE_SIZE> key;
	void* realMemory = nullptr;
	uintptr_t fakeMemoryAddress = 0;
	std::array<uint8_t, 12> nonce;
	mutable uint32_t lastChecksum = 0;
	bool isValid = false;

private:
	// Add a state structure to ensure consistent encryption/decryption
	struct CryptoState
	{
		alignas( T ) std::array<uint8_t, 32> fullKey;  // Always use 32-byte key
		std::array<uint8_t, VALUE_SIZE> temp;
	};

	void InitializeCryptoState ( CryptoState& cryptoState ) const
	{
		// Zero initialize the full key
		cryptoState.fullKey.fill ( 0 );

		// Copy our key into the full key buffer
		std::copy ( key.begin ( ), key.end ( ), cryptoState.fullKey.begin ( ) );

		// Zero initialize temp buffer
		cryptoState.temp.fill ( 0 );
	}

	void Obfuscate ( const T& value, std::array<uint8_t, VALUE_SIZE>& outBuffer ) const
	{
		CryptoState cryptoState;
		InitializeCryptoState ( cryptoState );

		// Copy value to temp buffer
		std::memcpy ( cryptoState.temp.data ( ), &value, VALUE_SIZE );

		// Encrypt with full key
		ChaCha20::Encrypt (
			cryptoState.temp.data ( ),
			outBuffer.data ( ),
			VALUE_SIZE,
			cryptoState.fullKey.data ( ),
			nonce.data ( )
		);
	}

	T Deobfuscate ( const std::array<uint8_t, VALUE_SIZE>& inBuffer ) const
	{
		CryptoState cryptoState;
		InitializeCryptoState ( cryptoState );

		// Decrypt with full key
		ChaCha20::Encrypt (
			inBuffer.data ( ),
			cryptoState.temp.data ( ),
			VALUE_SIZE,
			cryptoState.fullKey.data ( ),
			nonce.data ( )
		);

		T result;
		std::memcpy ( &result, cryptoState.temp.data ( ), VALUE_SIZE );
		return result;
	}

	bool ValidateMemory ( ) const
	{
		if ( !realMemory || !isValid ) return false;

		// Compare memory content with buffer
		std::array<uint8_t, sizeof ( T )> memContent;
		std::memcpy ( memContent.data ( ), realMemory, sizeof ( T ) );

		return ( memContent == buffer );
	}

	void GenerateKey ( std::array<uint8_t, VALUE_SIZE>& keyOut )
	{
		std::random_device rd;
		std::mt19937 gen ( rd ( ) );
		std::uniform_int_distribution<> dis ( 0, 255 );

		keyOut.fill ( 0 );  // Zero initialize first
		for ( size_t i = 0; i < VALUE_SIZE && i < 32; ++i ) {
			keyOut [ i ] = static_cast< uint8_t > ( dis ( gen ) );
		}
	}

public:
	SafeVar ( ) { Set ( T {} ); }
	SafeVar ( const T& value ) { Set ( value ); }
	~SafeVar ( ) { Clear ( ); }

	T Get ( bool encrypted = false ) const
	{
		if ( !realMemory ) {
			throw std::runtime_error ( "Invalid memory state" );
		}

		if ( !ValidateMemory ( ) ) {
			throw std::runtime_error ( "Memory validation failed" );
		}

		if ( encrypted ) {
			T raw;
			std::memcpy ( &raw, buffer.data ( ), VALUE_SIZE );
			return raw;
		}

		// First decryption
		T decrypted = Deobfuscate ( buffer );

		// Verify decryption by re-encrypting and comparing
		std::array<uint8_t, VALUE_SIZE> verify;
		Obfuscate ( decrypted, verify );

		if ( verify != buffer ) {
			throw std::runtime_error ( "Decryption verification failed" );
		}

		return decrypted;
	}

	const std::array<uint8_t, VALUE_SIZE>& GetInternalValue ( ) const
	{
		return buffer;
	}

	T Set ( const T& value )
	{
		Clear ( );
		GenerateKey ( key );
		GenerateNonce ( nonce );
		Obfuscate ( value, buffer );
		realMemory = RealMemoryAllocator::AllocateRealMemory ( VALUE_SIZE );
		if ( !realMemory ) throw std::runtime_error ( "Memory allocation failed" );
		std::memcpy ( realMemory, buffer.data ( ), VALUE_SIZE );
		lastChecksum = ComputeChecksumFNV ( buffer.data ( ), buffer.size ( ) );
		fakeMemoryAddress = FakeMemoryAllocator::AllocateFakeMemory ( VALUE_SIZE );
		isValid = true;
		return value;
	}

	void ReKey ( )
	{
		T current = Get ( );
		Set ( current );
	}

	operator T( ) const { return Get ( ); }

	void* operator new( size_t size )
	{
		return memoryPool.Allocate ( size );
	}

	void operator delete( void* ptr )
	{
		memoryPool.Free ( ptr );
	}

	SafeVar& operator=( const T& value )
	{
		Set ( value );
		return *this;
	}

	// Operator +=
	SafeVar& operator+=( const T& value )
	{
		T currentValue = Get ( );
		currentValue += value;
		Set ( currentValue );
		return *this;
	}

	// Operator -=
	SafeVar& operator-=( const T& value )
	{
		T currentValue = Get ( );
		currentValue -= value;
		Set ( currentValue );
		return *this;
	}

	// Operator *=
	SafeVar& operator*=( const T& value )
	{
		T currentValue = Get ( );
		currentValue *= value;
		Set ( currentValue );
		return *this;
	}

	// Operator /=
	SafeVar& operator/=( const T& value )
	{
		T currentValue = Get ( );
		currentValue /= value;
		Set ( currentValue );
		return *this;
	}

	// Operator %=
	SafeVar& operator%=( const T& value )
	{
		T currentValue = Get ( );
		currentValue %= value;
		Set ( currentValue );
		return *this;
	}

	// Comparison operators
	bool operator==( const SafeVar<T>& other ) const { return Get ( ) == other.Get ( ); }
	bool operator!=( const SafeVar<T>& other ) const { return Get ( ) != other.Get ( ); }
	bool operator<( const SafeVar<T>& other ) const { return Get ( ) < other.Get ( ); }
	bool operator<=( const SafeVar<T>& other ) const { return Get ( ) <= other.Get ( ); }
	bool operator>( const SafeVar<T>& other ) const { return Get ( ) > other.Get ( ); }
	bool operator>=( const SafeVar<T>& other ) const { return Get ( ) >= other.Get ( ); }

	// Unary increment and decrement operators
	SafeVar& operator++( )
	{
		T currentValue = Get ( );
		++currentValue;
		Set ( currentValue );
		return *this;
	}

	SafeVar operator++( int )
	{
		SafeVar temp = *this;
		++( *this );
		return temp;
	}

	SafeVar& operator--( )
	{
		T currentValue = Get ( );
		--currentValue;
		Set ( currentValue );
		return *this;
	}

	SafeVar operator--( int )
	{
		SafeVar temp = *this;
		--( *this );
		return temp;
	}

	// Real address manipulation: We store the real memory address
	uintptr_t GetRealAddress ( ) const
	{
		return reinterpret_cast< uintptr_t >( realMemory );
	}

	// Fake address manipulation: Return fake memory address (simulated for cheaters)
	uintptr_t GetFakeAddress ( ) const
	{
		return fakeMemoryAddress;
	}

	friend std::ostream& operator<<( std::ostream& os, const SafeVar& var )
	{
		return os << var.Get ( ); // This should use the Get() function to access the value.
	}

	std::array<uint8_t, VALUE_SIZE + 12 + VALUE_SIZE> Serialize ( ) const
	{
		std::array<uint8_t, VALUE_SIZE + 12 + VALUE_SIZE> out;

		// Store nonce (12 bytes for ChaCha20)
		std::memcpy ( out.data ( ), nonce.data ( ), 12 );

		// Store key (to ensure consistency during deserialization)
		std::memcpy ( out.data ( ) + 12, key.data ( ), VALUE_SIZE );

		// Encrypt buffer
		std::array<uint8_t, VALUE_SIZE> encrypted;
		ChaCha20::Encrypt ( buffer.data ( ), encrypted.data ( ), VALUE_SIZE, key.data ( ), nonce.data ( ) );

		// Append encrypted data
		std::memcpy ( out.data ( ) + 12 + VALUE_SIZE, encrypted.data ( ), VALUE_SIZE );

		return out;
	}

	bool Deserialize ( const uint8_t* data, size_t len )
	{
		if ( len != VALUE_SIZE + 12 + VALUE_SIZE ) return false;

		// Extract nonce
		std::memcpy ( nonce.data ( ), data, 12 );

		// Extract key (to ensure consistency during deserialization)
		std::memcpy ( key.data ( ), data + 12, VALUE_SIZE );

		// Extract encrypted payload
		std::array<uint8_t, VALUE_SIZE> encrypted;
		std::memcpy ( encrypted.data ( ), data + 12 + VALUE_SIZE, VALUE_SIZE );

		// Decrypt into buffer
		ChaCha20::Encrypt ( encrypted.data ( ), buffer.data ( ), VALUE_SIZE, key.data ( ), nonce.data ( ) );

		return true;
	}

	void Clear ( )
	{
		if ( realMemory ) {
			// Securely clear memory
			std::memset ( realMemory, 0, VALUE_SIZE );
			RealMemoryAllocator::FreeRealMemory ( realMemory );
			realMemory = nullptr;
		}

		// Clear sensitive data
		buffer.fill ( 0 );
		key.fill ( 0 );
		nonce.fill ( 0 );
		fakeMemoryAddress = 0;
	}
};

template<typename T>
MemoryPool SafeVar<T>::memoryPool;