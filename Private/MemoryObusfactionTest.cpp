#include <iostream>
#include <memory>
#include <chrono>
#include <thread>
#include <cmath>

// SafeVar
#include "../header/SafeVar.hpp"

struct PlayerPosition
{
    SafeVar<float> x, y, z;

    PlayerPosition ( float x_ = 0.f, float y_ = 0.f, float z_ = 0.f )
        : x ( x_ ), y ( y_ ), z ( z_ ) { }

    std::string ToString ( ) const
    {
        return "(" + std::to_string ( x.Get ( ) ) + ", "
            + std::to_string ( y.Get ( ) ) + ", "
            + std::to_string ( z.Get ( ) ) + ")";
    }
};

struct PlayerStats
{
    SafeVar<DWORD> health { 100 };
    SafeVar<DWORD> score { 0 };
    std::unique_ptr<PlayerPosition> position;

    PlayerStats ( int h = 100, int s = 0, float x = 0.f, float y = 0.f, float z = 0.f )
        : health ( h ), score ( s ), position ( std::make_unique<PlayerPosition> ( x, y, z ) ) { }

    void Print ( ) const
    {
        std::cout << "Health: " << health.Get ( ) << "\n"
            << "Score: " << score.Get ( ) << "\n"
            << "Position: " << position->ToString ( ) << "\n";
    }
};

void TestSymmetry ( )
{
    uint8_t key [ 32 ] = { 0x9f, 0x5d, 0x21, 0x6c }; // Example key
    uint8_t nonce [ 12 ] = { 0xcc, 0xbc, 0x54, 0xf1, 0x1, 0xf9, 0xf5, 0x7c, 0x78, 0x58, 0x6b, 0xeb }; // Example nonce
    uint8_t input [ 64 ] = { 0 }; // Example input
    uint8_t encrypted [ 64 ] = {};
    uint8_t decrypted [ 64 ] = {};

    // Encrypt
    ChaCha20::Encrypt ( input, encrypted, sizeof ( input ), key, nonce );

    // Decrypt
    ChaCha20::Encrypt ( encrypted, decrypted, sizeof ( input ), key, nonce );

    std::cout << "Original Input:\n";
    for ( int i = 0; i < 64; ++i ) {
        std::cout << std::hex << ( int ) input [ i ] << " ";
    }
    std::cout << "\n";

    std::cout << "Decrypted Output:\n";
    for ( int i = 0; i < 64; ++i ) {
        std::cout << std::hex << ( int ) decrypted [ i ] << " ";
    }
    std::cout << "\n";

    // Verify symmetry
    bool isSymmetric = std::equal ( std::begin ( input ), std::end ( input ), std::begin ( decrypted ) );
    if ( isSymmetric ) {
        std::cout << "Symmetry Test Passed!\n";
    }
    else {
        std::cout << "Symmetry Test Failed!\n";
    }
}

int main ( )
{
    try {
        // Create player stats for testing
        PlayerStats player ( 100, 0, 10.0f, 20.0f, 30.0f );

        std::cout << "Initial State:\n";
        player.Print ( );

        std::cout << "\nMemory Addresses:\n";
        std::cout << "Health - Real: " << std::dec << player.health.GetRealAddress ( )
            << " Fake: " << player.health.GetFakeAddress ( ) << "\n";
        std::cout << "Score - Real: " << std::dec << player.score.GetRealAddress ( )
            << " Fake: " << player.score.GetFakeAddress ( ) << "\n";

        // Continuous update loop to test memory protection
        std::cout << "\nStarting continuous update test (Press Ctrl+C to stop)...\n";
        int updateCount = 0;

        while ( true ) {
            // Update values
            player.health = 100 + ( updateCount % 50 );  // Health oscillates between 100-150
            player.score += 10;  // Score keeps increasing

            // Update position
            float x = 10.0f + static_cast< float >( std::sin ( updateCount * 0.1f ) * 5.0f );
            float y = 20.0f + static_cast< float >( std::cos ( updateCount * 0.1f ) * 5.0f );
            player.position->x = x;
            player.position->y = y;

            // Print current state
            std::cout << "\033[2J\033[1;1H";  // Clear screen and move cursor to top
            std::cout << "Update #" << std::dec << updateCount << "\n";
            player.Print ( );

            std::cout << "\nMemory Layout:\n";
            std::cout << "Health - Real: " << std::dec << player.health.GetRealAddress ( )
                << " Fake: " << player.health.GetFakeAddress ( )
                << " Value: " << player.health.Get ( ) << "\n";

            std::cout << "Score - Real: " << std::dec << player.score.GetRealAddress ( )
                << " Fake: " << player.score.GetFakeAddress ( )
                << " Value: " << player.score.Get ( ) << "\n";

            // Small delay to make updates visible
            std::this_thread::sleep_for ( std::chrono::seconds ( 15 ) );
            updateCount++;

            // Every 10 updates, trigger a rekey operation
            if ( updateCount % 15 == 0 ) {
                std::cout << "\nPerforming rekey operation...\n";
                player.health.ReKey ( );
                player.score.ReKey ( );
            }
        }

        return 0;
    }
    catch ( const std::exception& e ) {
        std::cerr << "Error: " << e.what ( ) << "\n";
        return 1;
    }
}



