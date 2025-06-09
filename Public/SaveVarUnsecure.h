#pragma once

#include <cstdint>
#include <cstring>
#include <type_traits>
#include <random>
#include <array>
#include <ostream>
#include <algorithm>

/**
 * @brief SafeVar<T>: A simple XOR-based memory obfuscation wrapper.
 *
 * Requirements:
 *  - T must be trivially copyable and default-constructible.
 *
 * Example:
 *   SafeVar<int> score = 100;
 *   score += 50;
 *   std::cout << score << "\n";
 *
 *   struct Vec3 { float x, y, z; };
 *   SafeVar<Vec3> pos = { {1.0f, 2.0f, 3.0f} };
 *   auto decrypted = pos.Get();
 */
template<typename T>
class SafeVar
{
    static_assert( std::is_trivially_copyable<T>::value&& std::is_default_constructible<T>::value,
        "SafeVar<T> requires trivially copyable and default-constructible types." );

private:
    static constexpr size_t SIZE = sizeof ( T );
    std::array<uint8_t, SIZE> buffer = {};
    std::array<uint8_t, SIZE> key = {};

    static void GenerateKey ( std::array<uint8_t, SIZE>& keyOut )
    {
        static std::mt19937_64 rng { std::random_device{}( ) };
        for ( size_t i = 0; i < SIZE; ++i )
            keyOut [ i ] = static_cast< uint8_t > ( rng ( ) & 0xFF );
    }

    void Obfuscate ( const T& value, std::array<uint8_t, SIZE>& outBuffer ) const
    {
        std::array<uint8_t, SIZE> raw;
        std::memcpy ( raw.data ( ), &value, SIZE );
        for ( size_t i = 0; i < SIZE; ++i )
            outBuffer [ i ] = raw [ i ] ^ key [ i ];
    }

    T Deobfuscate ( const std::array<uint8_t, SIZE>& inBuffer ) const
    {
        std::array<uint8_t, SIZE> raw;
        for ( size_t i = 0; i < SIZE; ++i )
            raw [ i ] = inBuffer [ i ] ^ key [ i ];
        T result;
        std::memcpy ( &result, raw.data ( ), SIZE );
        return result;
    }

public:
    // Default-initialized
    SafeVar ( ) { Set ( T {} ); }

    // Construct with initial value
    SafeVar ( const T& value ) { Set ( value ); }

    // Get decrypted value (or raw encrypted buffer if encrypted == true)
    T Get ( bool encrypted = false ) const
    {
        if ( encrypted ) {
            T raw;
            std::memcpy ( &raw, buffer.data ( ), SIZE );
            return raw;
        }
        return Deobfuscate ( buffer );
    }

    // Obfuscate and store a new value
    T Set ( const T& value )
    {
        GenerateKey ( key );
        Obfuscate ( value, buffer );
        return value;
    }

    // Re-encrypt current value with a new key
    void ReKey ( )
    {
        T current = Get ( );
        Set ( current );
    }

    // Implicit conversion to T
    operator T( ) const { return Get ( ); }

    // Assign new value
    SafeVar& operator=( const T& value )
    {
        Set ( value );
        return *this;
    }

    // Arithmetic operators (enabled only for arithmetic types)
    template<typename U = T>
    typename std::enable_if<std::is_arithmetic<U>::value, SafeVar&>::type operator+=( const T& rhs )
    {
        Set ( Get ( ) + rhs ); return *this;
    }

    template<typename U = T>
    typename std::enable_if<std::is_arithmetic<U>::value, SafeVar&>::type operator-=( const T& rhs )
    {
        Set ( Get ( ) - rhs ); return *this;
    }

    template<typename U = T>
    typename std::enable_if<std::is_arithmetic<U>::value, SafeVar&>::type operator*=( const T& rhs )
    {
        Set ( Get ( ) * rhs ); return *this;
    }

    template<typename U = T>
    typename std::enable_if<std::is_arithmetic<U>::value, SafeVar&>::type operator/=( const T& rhs )
    {
        Set ( Get ( ) / rhs ); return *this;
    }

    template<typename U = T>
    typename std::enable_if<std::is_arithmetic<U>::value, SafeVar&>::type operator++( )
    {
        Set ( Get ( ) + 1 ); return *this;
    }

    template<typename U = T>
    typename std::enable_if<std::is_arithmetic<U>::value, SafeVar&>::type operator--( )
    {
        Set ( Get ( ) - 1 ); return *this;
    }

    // Comparison operators with plain T
    bool operator==( const T& rhs ) const { return Get ( ) == rhs; }
    bool operator!=( const T& rhs ) const { return Get ( ) != rhs; }
    bool operator< ( const T& rhs ) const { return Get ( ) < rhs; }
    bool operator<=( const T& rhs ) const { return Get ( ) <= rhs; }
    bool operator> ( const T& rhs ) const { return Get ( ) > rhs; }
    bool operator>=( const T& rhs ) const { return Get ( ) >= rhs; }

    // Comparison operators with another SafeVar<T>
    bool operator==( const SafeVar& rhs ) const { return Get ( ) == rhs.Get ( ); }
    bool operator!=( const SafeVar& rhs ) const { return Get ( ) != rhs.Get ( ); }

    // Stream output
    friend std::ostream& operator<<( std::ostream& os, const SafeVar& var )
    {
        return os << var.Get ( );
    }

    // Optional array indexing (only valid for array types)
    template<typename U = T>
    typename std::enable_if<std::is_array<U>::value, typename std::remove_extent<U>::type>::type
        operator[]( size_t index ) const
    {
        T value = Get ( );
        return value [ index ];
    }

    // Serialize to buffer (key + encrypted buffer)
    std::array<uint8_t, SIZE * 2> Serialize ( ) const
    {
        std::array<uint8_t, SIZE * 2> out;
        std::memcpy ( out.data ( ), key.data ( ), SIZE );
        std::memcpy ( out.data ( ) + SIZE, buffer.data ( ), SIZE );
        return out;
    }

    // Load from serialized buffer
    bool Deserialize ( const uint8_t* data, size_t len )
    {
        if ( len != SIZE * 2 ) return false;
        std::memcpy ( key.data ( ), data, SIZE );
        std::memcpy ( buffer.data ( ), data + SIZE, SIZE );
        return true;
    }

    // Securely clear memory
    void Clear ( )
    {
        std::fill ( buffer.begin ( ), buffer.end ( ), 0 );
        std::fill ( key.begin ( ), key.end ( ), 0 );
    }
};
