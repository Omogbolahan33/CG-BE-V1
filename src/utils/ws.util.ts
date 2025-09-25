// src/utils/ws.util.ts

/**
 * STUB: Simulates emitting a WebSocket event to a client.
 * In a real application, this would use the global Socket.IO instance (io.emit).
 * * @param eventName The name of the event (e.g., 'userUpdate:userId')
 * @param data The payload (public-safe user data)
 */
export const emitWebSocketEvent = (eventName: string, data: any): void => {
    // In a real application, this would be:
    // io.emit(eventName, data); 
    
    console.log(
        `[WS STUB] Emitted event: ${eventName}`,
        `\n[WS STUB] Payload Keys: ${Object.keys(data).join(', ')}`
    );
};
