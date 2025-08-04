use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    println!("Trying to open IDA database...");

    // Open IDA database
    let idb = IDB::open("./tests/ls")?;

    println!("Testing types API...");

    // Test getting type list length
    let types = idb.types();
    let len = types.len();
    println!("Found {} types in database", len);

    // Test iterating through first few types
    println!("\nFirst 10 types:");
    for i in 1..std::cmp::min(len, 10) {
        if let Some(typ) = types.get_by_index(i as u32) {
            if let Some(name) = typ.name() {
                println!("  Type {} (ordinal {}): {}", i, typ.ordinal(), name);
            } else {
                println!("  Type {} (ordinal {}): <unnamed>", i, typ.ordinal());
            }
        }
    }

    // Test type iterator
    println!("\nTesting type iterator (first 5):");
    for (ordinal, typ) in types.iter().take(5) {
        if let Some(name) = typ.name() {
            println!("  Iterator type ordinal {}: {}", ordinal, name);
        } else {
            println!("  Iterator type ordinal {}: <unnamed>", ordinal);
        }
    }

    // Test type assignment functionality
    println!("\nTesting type assignment...");

    // Get the first function in the database
    if let Some((_, mut func)) = idb.functions().nth(0) {
        let func_addr = func.start_address();
        println!("Testing with function at address: {:#x}", func_addr);

        // Check current type
        if let Some(current_type) = func.get_type() {
            println!("Current function type: {:?}", current_type.name());
        } else {
            println!("Function has no assigned type");
        }

        // Try to find an existing type to apply to the function
        // Let's look for a simple integer type or void type
        if let Some(test_type) = types.get_by_index(1) {
            if let Some(type_name) = test_type.name() {
                println!("Attempting to apply type '{}' to function", type_name);
                match func.set_type(&test_type) {
                    Ok(()) => println!("Successfully applied type to function"),
                    Err(e) => println!("Failed to apply type: {}", e),
                }

                // Check if we can retrieve the type we just set
                if let Some(new_type) = func.get_type() {
                    println!("New type after assignment: {:?}", new_type.name());
                }
            }
        }
    } else {
        println!("No functions found in database");
    }

    // Test address-based type assignment
    println!("\nTesting address-based type assignment...");

    // Get the first segment's start address for testing
    if let Some((_, segment)) = idb.segments().nth(0) {
        let test_address = segment.start_address();
        println!("Testing with address: {:#x}", test_address);

        // Check current type at address
        if let Some(addr_type) = idb.get_type_at_address(test_address) {
            println!("Current type at address: {:?}", addr_type.name());
        } else {
            println!("No type assigned at address");
        }

        // Try to apply a type from our type list to the address
        if let Some(test_type) = types.get_by_index(1) {
            if let Some(type_name) = test_type.name() {
                println!("Attempting to apply type '{}' to address", type_name);
                match test_type.apply_to_address(test_address) {
                    Ok(()) => println!("Successfully applied type to address"),
                    Err(e) => println!("Failed to apply type to address: {}", e),
                }

                // Check if we can retrieve the type we just set
                if let Some(new_addr_type) = idb.get_type_at_address(test_address) {
                    println!("New type at address: {:?}", new_addr_type.name());
                }
            }
        }
    } else {
        println!("No segments found in database");
    }

    println!("\nType assignment API test completed!");
    Ok(())
}
